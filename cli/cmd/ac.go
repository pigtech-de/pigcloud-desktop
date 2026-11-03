package cmd

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"pigcloud/internal/api"
	"pigcloud/internal/cmdutil"
	"pigcloud/internal/crypto"
	"pigcloud/internal/e2ee"
	"pigcloud/internal/fsutil"
	"pigcloud/internal/output"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var (
	acLimit    int
	acOffset   int
	acUnread   bool
	acMarkRead string
	acType     string
	acSince    string
	acUntil    string
	acFollow   bool
)

var acCmd = &cobra.Command{
	Use:     "ac",
	GroupID: GroupTools,
	Aliases: []string{"activity"},
	Short:   "View activity log and notifications",
	Long:    `View your recent activity and notifications.`,
	Example: `pc ac                             # Show recent activity
pc ac -u                          # Show only unread notifications
pc ac -n 5                        # Show last 5 events
pc ac -t login,share_sent         # Filter by event type(s)
pc ac --since 2026-05-01          # Only events on or after a date
pc ac -f                          # Follow: print new events as they happen
pc ac -m all                      # Mark all as read
pc ac -m 42                       # Mark a specific event as read`,
	Args: cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		runActivity()
	},
}

func init() {
	rootCmd.AddCommand(acCmd)
	acCmd.Flags().IntVarP(&acLimit, "limit", "n", 20, "maximum number of events to show")
	acCmd.Flags().IntVarP(&acOffset, "offset", "o", 0, "number of events to skip")
	acCmd.Flags().BoolVarP(&acUnread, "unread", "u", false, "show only unread notifications")
	acCmd.Flags().StringVarP(&acMarkRead, "mark-read", "m", "", "mark events as read: 'all' or an event ID")
	acCmd.RegisterFlagCompletionFunc("mark-read", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return []string{"all\tMark all as read"}, cobra.ShellCompDirectiveNoFileComp
	})
	acCmd.Flags().StringVarP(&acType, "type", "t", "", "filter by event type(s), comma-separated (e.g. login,share_sent)")
	acCmd.Flags().StringVar(&acSince, "since", "", "only events on or after this date (YYYY-MM-DD)")
	acCmd.Flags().StringVar(&acUntil, "until", "", "only events on or before this date (YYYY-MM-DD)")
	acCmd.Flags().BoolVarP(&acFollow, "follow", "f", false, "poll for new events until interrupted")
}

func runActivity() {
	ctx, cancel := cmdutil.StartAuthed(ExitWithError)
	defer cancel()

	options := map[string]string{
		"limit": fmt.Sprintf("%d", acLimit),
	}
	if acOffset > 0 {
		options["offset"] = fmt.Sprintf("%d", acOffset)
	}
	if acUnread {
		options["unread"] = "true"
	}
	if acMarkRead != "" {
		options["mark-read"] = acMarkRead
	}
	if acType != "" {
		options["type"] = acType
	}
	if acSince != "" {
		options["since"] = acSince
	}
	if acUntil != "" {
		options["until"] = acUntil
	}

	if acFollow {
		if acMarkRead != "" || acOffset > 0 {
			output.PrintError("--follow cannot be combined with --mark-read or --offset")
			ExitWithError()
		}
		followActivity(ctx, options)
		return
	}

	_, payload := cmdutil.ExecuteCommand[api.ActivityPayload](ctx, "ac", options, ExitWithError)

	if acMarkRead == "" {
		labelEvents(payload.Events, payload.EventLabels)
	}
	payload.EventLabels = nil

	if cmdutil.PrintJSONOrContinue(GetJSONOutput(), payload) {
		return
	}

	if acMarkRead != "" {
		output.PrintSuccess(fmt.Sprintf("Marked %d event(s) as read", payload.MarkedRead))
		return
	}

	if len(payload.Events) == 0 {
		if acUnread {
			output.PrintInfo("No unread notifications")
		} else {
			output.PrintInfo("No activity")
		}
		return
	}

	unreadLabel := ""
	if payload.UnreadCount > 0 {
		unreadLabel = color.YellowString(fmt.Sprintf(" (%d unread)", payload.UnreadCount))
	}
	fmt.Printf("Activity%s\n\n", unreadLabel)

	for _, event := range payload.Events {
		marker := "  "
		if event.ReadAt == nil {
			marker = color.YellowString("* ")
		}

		fmt.Printf("%s%s\n", marker, eventLine(event))
	}

	if acOffset > 0 {
		fmt.Printf("\nShowing %d-%d of %d events\n", acOffset+1, acOffset+len(payload.Events), payload.TotalCount)
	} else {
		fmt.Printf("\nShowing %d of %d events\n", len(payload.Events), payload.TotalCount)
	}
}

const followPollInterval = 5 * time.Second

func followActivity(ctx context.Context, options map[string]string) {
	lastID := 0
	first := true

	for {
		resp, err := api.NewClient().Execute(ctx, "ac", cloneOptions(options))
		if ctx.Err() != nil {
			return
		}
		if err == nil && resp.Success {
			var payload api.ActivityPayload
			if jsonErr := json.Unmarshal(resp.Raw, &payload); jsonErr == nil {
				fresh := make([]api.ActivityEvent, 0, len(payload.Events))
				for _, event := range payload.Events {
					if event.ID > lastID {
						fresh = append(fresh, event)
					}
				}
				labelEvents(fresh, payload.EventLabels)
				for _, event := range slices.Backward(fresh) {
					if event.ID > lastID {
						lastID = event.ID
					}
					printFollowEvent(event)
				}
				if first && len(fresh) == 0 && !GetJSONOutput() {
					output.PrintInfo("Waiting for activity... (Ctrl+C to stop)")
				}
				first = false
			}
		} else if !GetJSONOutput() {
			msg := "unreachable"
			if err != nil {
				msg = err.Error()
			} else if resp != nil {
				msg = resp.Message
			}
			fmt.Fprintf(os.Stderr, "%s\n", color.HiBlackString("poll failed (retrying): "+msg))
		}

		select {
		case <-ctx.Done():
			return
		case <-time.After(followPollInterval):
		}
	}
}

func printFollowEvent(event api.ActivityEvent) {
	if GetJSONOutput() {
		line, err := json.Marshal(event)
		if err == nil {
			fmt.Println(string(line))
		}
		return
	}
	fmt.Println(eventLine(event))
}

func labelEvents(events []api.ActivityEvent, labels map[string]api.ActivityLabel) {
	for i := range events {
		unwrapEvent(&events[i])
		if l, ok := labels[events[i].EventType]; ok {
			events[i].Label, events[i].Tone = l.Label, l.Tone
		}
	}
}

func eventLine(event api.ActivityEvent) string {
	label := fsutil.StripControl(event.EventType)
	if event.Label != "" {
		label = output.Styled(event.Tone, fsutil.StripControl(event.Label))
	}
	detail := formatEventDetail(event.EventType, resolveNodeRefs(event.Detail))
	timestamp := fsutil.StripControl(output.FormatTime(&event.CreatedAt))
	return fmt.Sprintf("%-18s %s  %s", label, color.HiBlackString(timestamp), detail)
}

func cloneOptions(options map[string]string) map[string]string {
	c := make(map[string]string, len(options))
	maps.Copy(c, options)
	return c
}

func decryptEventDetail(detail string) string {
	if detail == "" {
		return ""
	}
	if !e2ee.HasE2EEKeys() {
		return detail
	}
	sealed, err := base64.StdEncoding.DecodeString(detail)
	if err != nil {
		return detail
	}
	_, privKey := cmdutil.GetKeyPair(func() {})
	if privKey == nil {
		return detail
	}
	plaintext, err := crypto.UnsealDisplayName(sealed, privKey)
	if err != nil {
		return detail
	}
	return plaintext
}

type sealedActivityDetail struct {
	Type    string `json:"type"`
	Payload string `json:"payload"`
}

func unwrapEvent(event *api.ActivityEvent) {
	detail := decryptEventDetail(event.Detail)
	if strings.HasPrefix(detail, "{") {
		var wrapped sealedActivityDetail
		if json.Unmarshal([]byte(detail), &wrapped) == nil && wrapped.Type != "" {
			if event.EventType == "" {
				event.EventType = wrapped.Type
			}
			detail = wrapped.Payload
		}
	}
	event.Detail = stripActivityMetaTag(detail)
}

func stripActivityMetaTag(detail string) string {
	if detail == "" {
		return ""
	}
	parts := strings.Split(detail, "\n")
	last := parts[len(parts)-1]
	if last == "cli" || last == "assistant" || strings.HasPrefix(last, "cli:") {
		return strings.Join(parts[:len(parts)-1], "\n")
	}
	return detail
}

var (
	nodeRefRe       = regexp.MustCompile(`(?i)\bnode:[a-f0-9]+\b`)
	nodePathsOnce   sync.Once
	nodePathsByID   map[string]string
	nodePathUnknown = "(unknown item)"
)

func resolveNodeRefs(detail string) string {
	if !strings.Contains(detail, "node:") {
		return detail
	}
	detail = strings.ReplaceAll(detail, "node:mkdir", "")
	return nodeRefRe.ReplaceAllStringFunc(detail, func(m string) string {
		nodePathsOnce.Do(func() { nodePathsByID = fetchNodePaths() })
		if p := nodePathsByID[strings.ToLower(strings.TrimPrefix(m, "node:"))]; p != "" {
			return p
		}
		return nodePathUnknown
	})
}

func fetchNodePaths() map[string]string {
	if !e2ee.HasE2EEKeys() {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	resp, err := api.NewClient().Execute(ctx, "fd", map[string]string{
		"pattern": "*",
		"source":  "/",
		"limit":   "10000",
		"all":     "true",
	})
	if err != nil || !resp.Success {
		return nil
	}
	var payload api.FindPayload
	if json.Unmarshal(resp.Raw, &payload) != nil {
		return nil
	}

	nameByID := make(map[string]string, len(payload.Results))
	parentByID := make(map[string]string, len(payload.Results))
	for i := range payload.Results {
		entry := &payload.Results[i]
		name := e2ee.ResolveName(entry.E2EEDisplayName, entry.Name)
		if entry.ID == "" || e2ee.IsNameUnavailable(name) {
			continue
		}
		id := strings.ToLower(entry.ID)
		nameByID[id] = name
		parentByID[id] = strings.ToLower(entry.ParentID)
	}

	paths := make(map[string]string, len(nameByID))
	for id := range nameByID {
		var segments []string
		seen := make(map[string]struct{}, 8)
		for cur := id; cur != ""; {
			if _, loop := seen[cur]; loop {
				break
			}
			seen[cur] = struct{}{}
			name, ok := nameByID[cur]
			if !ok {
				break
			}
			segments = append([]string{name}, segments...)
			cur = parentByID[cur]
		}
		paths[id] = strings.Join(segments, "/")
	}
	return paths
}

func formatEventDetail(eventType, detail string) string {
	if detail == "" {
		return ""
	}
	parts := strings.Split(detail, "\n")
	for i := range parts {
		parts[i] = fsutil.StripControl(parts[i])
	}
	permSuffix := ""
	if len(parts) >= 3 && (parts[2] == "edit" || parts[2] == "read") {
		if parts[2] == "edit" {
			permSuffix = " (edit)"
		} else {
			permSuffix = " (read-only)"
		}
	}
	switch eventType {
	case "share_sent":
		if len(parts) >= 2 {
			return output.PrintPath(parts[0]) + " to " + parts[1] + permSuffix
		}
	case "share_received":
		if len(parts) >= 2 {
			return output.PrintPath(parts[0]) + " from " + parts[1] + permSuffix
		}
	case "share_expired", "share_rejected":
		if len(parts) >= 2 {
			return output.PrintPath(parts[0]) + " (" + parts[1] + ")"
		}
	}
	return parts[0]
}
