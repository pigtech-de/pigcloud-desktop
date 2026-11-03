package e2ee

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"pigcloud/internal/api"
)

const (
	CodeNodeIDTaken = "node_id_taken"
	CodePathChanged = "path_changed"
	CodePathExists  = "path_exists"
)

var ErrRemoteMissing = errors.New("remote path not found")

type missingDirError string

func (e missingDirError) Error() string { return "directory not found: " + string(e) }

func (e missingDirError) Unwrap() error { return ErrRemoteMissing }

type RemoteNode struct {
	ID    string
	IsDir bool
}

var nodeIDHexPattern = regexp.MustCompile(`\A[0-9a-fA-F]{32}\z`)

func IsNodeIDHex(s string) bool { return nodeIDHexPattern.MatchString(s) }

func (s *Session) StatRemote(ctx context.Context, exec api.Executor, remotePath string) (RemoteNode, error) {
	if strings.Trim(remotePath, "/") == "" {
		return RemoteNode{IsDir: true}, nil
	}
	options := map[string]string{"source": remotePath}
	if err := s.AddPathTokensFor(options, remotePath, SelfAndParent); err != nil {
		return RemoteNode{}, err
	}
	resp, err := exec.Execute(ctx, "in", options)
	if err != nil {
		return RemoteNode{}, err
	}
	if resp == nil {
		return RemoteNode{}, errors.New("empty response to a path lookup")
	}
	if !resp.Success {
		if resp.StatusCode == http.StatusNotFound {
			return RemoteNode{}, ErrRemoteMissing
		}
		return RemoteNode{}, errors.New(resp.Message)
	}
	var payload api.InfoPayload
	if err := json.Unmarshal(resp.Raw, &payload); err != nil {
		return RemoteNode{}, fmt.Errorf("parse path lookup: %w", err)
	}
	if !IsNodeIDHex(payload.Details.NodeID) {
		return RemoteNode{}, fmt.Errorf("the server named no node id for %s", remotePath)
	}
	return RemoteNode{ID: strings.ToLower(payload.Details.NodeID), IsDir: payload.Details.Type == "directory"}, nil
}

func (s *Session) ResolveDirID(ctx context.Context, exec api.Executor, remotePath string) (string, error) {
	node, err := s.StatRemote(ctx, exec, remotePath)
	if errors.Is(err, ErrRemoteMissing) {
		return "", missingDirError(remotePath)
	}
	if err != nil {
		return "", fmt.Errorf("could not resolve %s: %w", remotePath, err)
	}
	if !node.IsDir {
		return "", fmt.Errorf("not a directory: %s", remotePath)
	}
	return node.ID, nil
}

func (s *Session) MintRefIn(ctx context.Context, exec api.Executor, dirPath string, parentKey []byte) (NodeRef, error) {
	parentID, err := s.ResolveDirID(ctx, exec, dirPath)
	if err != nil {
		return NodeRef{}, err
	}
	return MintSealedNode(parentID, parentKey)
}

type MkParentsPlan struct {
	Segments []string
	Refs     []NodeRef
	LeafID   string
	Creates  bool
}

func PathSegments(remotePath string) []string {
	var out []string
	for seg := range strings.SplitSeq(strings.Trim(remotePath, "/"), "/") {
		seg = strings.TrimSpace(seg)
		if seg != "" && seg != "." && seg != ".." {
			out = append(out, seg)
		}
	}
	return out
}

func (s *Session) PlanMkParents(ctx context.Context, exec api.Executor, remotePath string, parentKey []byte) (MkParentsPlan, error) {
	plan := MkParentsPlan{Segments: PathSegments(remotePath)}
	existing, ancestorID, err := s.deepestExistingPrefix(ctx, exec, plan.Segments)
	if err != nil {
		return plan, err
	}
	return PlanFromProbe(plan.Segments, existing, ancestorID, parentKey)
}

func PlanFromProbe(segments []string, existing int, ancestorID string, parentKey []byte) (MkParentsPlan, error) {
	plan := MkParentsPlan{Segments: segments, LeafID: ancestorID}
	refs, err := ChainSegmentRefs(len(segments), existing, ancestorID, parentKey)
	if err != nil {
		return plan, err
	}
	plan.Refs = refs
	if existing < len(segments) {
		plan.LeafID = refs[len(refs)-1].ID
		plan.Creates = true
	}
	return plan, nil
}

func (s *Session) deepestExistingPrefix(ctx context.Context, exec api.Executor, segments []string) (int, string, error) {
	for i := len(segments); i > 0; i-- {
		prefix := "/" + strings.Join(segments[:i], "/")
		node, err := s.StatRemote(ctx, exec, prefix)
		if errors.Is(err, ErrRemoteMissing) {
			continue
		}
		if err != nil {
			return 0, "", fmt.Errorf("could not resolve %s: %w", prefix, err)
		}
		if !node.IsDir {
			return 0, "", fmt.Errorf("not a directory: %s", prefix)
		}
		return i, node.ID, nil
	}
	return 0, "", nil
}

func ChainSegmentRefs(total, existing int, ancestorID string, parentKey []byte) ([]NodeRef, error) {
	refs := make([]NodeRef, total)
	parent := ancestorID
	for i := existing; i < total; i++ {
		ref, err := MintSealedNode(parent, parentKey)
		if err != nil {
			return nil, err
		}
		refs[i] = ref
		parent = ref.ID
	}
	return refs, nil
}

type SegmentID struct {
	NodeID  string `json:"node_id"`
	Existed bool   `json:"existed"`
}

type FolderChain struct {
	Resp    *api.Response
	LeafID  string
	Created bool
}

func (s *Session) EnsureFolderChain(ctx context.Context, exec api.Executor, remotePath string, parentKey []byte) (FolderChain, error) {
	for attempt := 0; ; attempt++ {
		options := map[string]string{"source": remotePath, "parents": "true"}
		if err := s.AddPathTokensFor(options, remotePath, SelfAndParent); err != nil {
			return FolderChain{}, err
		}
		if parentKey == nil {
			if err := s.AddE2eeNameFieldsForMkParents(options, PathSegments(remotePath)); err != nil {
				return FolderChain{}, err
			}
			resp, err := exec.Execute(ctx, "mk", options)
			return FolderChain{Resp: resp}, err
		}
		plan, err := s.PlanMkParents(ctx, exec, remotePath, parentKey)
		if err != nil {
			return FolderChain{}, err
		}
		if err := s.AddE2eeNameFieldsForMkParentsWithRefs(options, plan.Segments, plan.Refs); err != nil {
			return FolderChain{}, err
		}
		resp, err := exec.Execute(ctx, "mk", options)
		if err != nil || resp == nil {
			return FolderChain{Resp: resp}, err
		}
		if !resp.Success {
			if attempt == 0 && (resp.ErrorCode == CodePathChanged || resp.ErrorCode == CodeNodeIDTaken) {
				continue
			}
			return FolderChain{Resp: resp}, nil
		}
		return s.confirmFolderChain(ctx, exec, remotePath, plan, resp)
	}
}

func (s *Session) confirmFolderChain(ctx context.Context, exec api.Executor, remotePath string, plan MkParentsPlan, resp *api.Response) (FolderChain, error) {
	chain := FolderChain{Resp: resp, LeafID: plan.LeafID, Created: plan.Creates}
	var echo struct {
		SegmentIDs []SegmentID `json:"segment_ids"`
	}
	if json.Unmarshal(resp.Raw, &echo) == nil && len(echo.SegmentIDs) == len(plan.Segments) && len(plan.Segments) > 0 {
		leaf := echo.SegmentIDs[len(echo.SegmentIDs)-1]
		if IsNodeIDHex(leaf.NodeID) {
			chain.LeafID, chain.Created = strings.ToLower(leaf.NodeID), !leaf.Existed
			return chain, nil
		}
	}
	if !plan.Creates {
		return chain, nil
	}
	node, err := s.StatRemote(ctx, exec, remotePath)
	if err != nil {
		return chain, fmt.Errorf("could not resolve %s after creating it: %w", remotePath, err)
	}
	chain.LeafID = node.ID
	return chain, nil
}

func SendCreate(send func() (*api.Response, error), remint func() error) (*api.Response, error) {
	resp, err := send()
	if !api.HasErrorCode(resp, err, CodeNodeIDTaken) || remint == nil {
		return resp, err
	}
	if rerr := remint(); rerr != nil {
		return nil, rerr
	}
	return send()
}
