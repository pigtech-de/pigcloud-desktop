package mobile

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"pigcloud/internal/api"
)

const (
	WakeContinue = "continue"
	WakePause    = "pause"
	WakeWipe     = "wipe"

	RevocationMarker = "deviceTokenRevoked"

	revocationConfirmDelay = 30 * time.Second

	wakeTimeout = 45 * time.Second
)

var wakeNow = time.Now

type wakeRequest struct {
	KeyEpoch           int64  `json:"key_epoch"`
	KeyIdentifier      string `json:"key_identifier"`
	RevocationStrikeAt int64  `json:"revocation_strike_at"`
}

type wakeResult struct {
	Outcome            string `json:"outcome"`
	Reason             string `json:"reason"`
	KeyEpoch           int64  `json:"key_epoch"`
	RetryAfterSeconds  int    `json:"retry_after_seconds"`
	RevocationStrikeAt int64  `json:"revocation_strike_at"`
}

type wakeBody struct {
	Success   bool   `json:"success"`
	ErrorCode string `json:"errorCode"`
	Ident     string `json:"identifier"`
	Username  string `json:"username"`
	KeyEpoch  *int64 `json:"key_epoch"`
}

func (s *Session) CheckKeys(requestJSON string) (out string, err error) {
	defer recovered("CheckKeys", &err)

	var req wakeRequest
	if err := json.Unmarshal([]byte(requestJSON), &req); err != nil {
		return "", errors.New("parse wake request: " + err.Error())
	}

	ctx, cancel := context.WithTimeout(context.Background(), wakeTimeout)
	defer cancel()
	resp, callErr := api.NewClient().Execute(ctx, "wh", map[string]string{})
	return encodeJSON(decideWake(req, resp, callErr, enrolmentOpen(), wakeNow()))
}

func enrolmentOpen() bool {
	enrolMu.Lock()
	defer enrolMu.Unlock()
	return enrolLive != nil
}

func decideWake(req wakeRequest, resp *api.Response, callErr error, enrolOpen bool, now time.Time) wakeResult {
	pause := func(reason string, retryAfter int) wakeResult {
		return wakeResult{Outcome: WakePause, Reason: reason, KeyEpoch: req.KeyEpoch, RetryAfterSeconds: retryAfter}
	}
	if callErr != nil || resp == nil {
		if callErr != nil && strings.Contains(callErr.Error(), "parse response") {
			return pause("malformed", 0)
		}
		return pause("unreachable", 0)
	}

	var body wakeBody
	bodyOK := len(resp.Raw) > 0 && json.Unmarshal(resp.Raw, &body) == nil

	switch {
	case resp.StatusCode == 429:
		return pause("rate_limited", 0)
	case resp.StatusCode >= 500:
		return pause("server_error", 0)
	case resp.StatusCode == 401 || resp.StatusCode == 403:
		if !bodyOK || body.ErrorCode != RevocationMarker || req.KeyIdentifier == "" || !strings.EqualFold(body.Ident, req.KeyIdentifier) {
			return pause("unauthorized", 0)
		}
		if enrolOpen {
			result := pause("enrolment_open", int(revocationConfirmDelay/time.Second))
			result.RevocationStrikeAt = req.RevocationStrikeAt
			return result
		}
		if req.RevocationStrikeAt > 0 {
			first := time.Unix(req.RevocationStrikeAt, 0)
			if elapsed := now.Sub(first); elapsed >= revocationConfirmDelay {
				return wakeResult{Outcome: WakeWipe, Reason: "revoked", KeyEpoch: req.KeyEpoch}
			} else if elapsed >= 0 {
				result := pause("revocation_unconfirmed", int((revocationConfirmDelay-elapsed)/time.Second)+1)
				result.RevocationStrikeAt = req.RevocationStrikeAt
				return result
			}
		}
		result := pause("revocation_unconfirmed", int(revocationConfirmDelay/time.Second))
		result.RevocationStrikeAt = now.Unix()
		return result
	case resp.StatusCode >= 400:
		return pause("refused", 0)
	}

	if !bodyOK || !body.Success || body.Username == "" {
		return pause("malformed", 0)
	}
	if body.KeyEpoch == nil {
		return wakeResult{Outcome: WakeContinue, Reason: "epoch_unknown", KeyEpoch: req.KeyEpoch}
	}
	serverEpoch := *body.KeyEpoch
	if serverEpoch > req.KeyEpoch {
		if enrolOpen {
			return pause("enrolment_open", int(revocationConfirmDelay/time.Second))
		}
		return wakeResult{Outcome: WakeWipe, Reason: "key_rotated", KeyEpoch: serverEpoch}
	}
	if serverEpoch < req.KeyEpoch {
		return pause("epoch_behind", 0)
	}
	return wakeResult{Outcome: WakeContinue, Reason: "current", KeyEpoch: req.KeyEpoch}
}
