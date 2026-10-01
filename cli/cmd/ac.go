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
		for i := range payload.Events {
			unwrapEvent(&payload.Events[i])
		}
	}

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

		typeLabel := formatEventType(event.EventType)
		detail := formatEventDetail(event.EventType, resolveNodeRefs(event.Detail))
		timestamp := output.FormatTime(&event.CreatedAt)

		fmt.Printf("%s%-18s %s  %s\n", marker, typeLabel, color.HiBlackString(timestamp), detail)
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
	unwrapEvent(&event)
	if GetJSONOutput() {
		line, err := json.Marshal(event)
		if err == nil {
			fmt.Println(string(line))
		}
		return
	}
	typeLabel := formatEventType(event.EventType)
	detail := formatEventDetail(event.EventType, resolveNodeRefs(event.Detail))
	timestamp := output.FormatTime(&event.CreatedAt)
	fmt.Printf("%-18s %s  %s\n", typeLabel, color.HiBlackString(timestamp), detail)
}

func cloneOptions(options map[string]string) map[string]string {
	c := make(map[string]string, len(options))
	maps.Copy(c, options)
	return c
}

func formatEventType(eventType string) string {
	switch eventType {
	case "account_created":
		return color.GreenString("Account created")
	case "login":
		return color.GreenString("Login")
	case "new_device_login":
		return color.YellowString("New device login")
	case "login_attempts_throttled":
		return color.YellowString("Login attempts throttled")
	case "password_change":
		return color.YellowString("Password changed")
	case "email_change":
		return color.YellowString("Email changed")
	case "two_factor_change":
		return color.YellowString("2FA changed")
	case "passkey_registered":
		return color.CyanString("Passkey registered")
	case "passkey_removed":
		return color.YellowString("Passkey removed")
	case "session_revoked":
		return color.YellowString("Session revoked")
	case "api_key_created":
		return color.CyanString("API key created")
	case "api_key_revoked":
		return color.YellowString("API key revoked")
	case "e2ee_key_rotation":
		return color.CyanString("E2EE keys rotated")
	case "fido2_tfa_change":
		return color.YellowString("FIDO2 2FA changed")
	case "recovery_codes_generated":
		return color.YellowString("Recovery codes generated")
	case "oauth_linked":
		return color.YellowString("External account linked")
	case "oauth_unlinked":
		return color.YellowString("External account unlinked")
	case "activity_cleared":
		return color.YellowString("Activity log cleared")
	case "file_uploaded":
		return "File uploaded"
	case "file_downloaded":
		return "File downloaded"
	case "file_deleted":
		return "File deleted"
	case "file_moved":
		return "File moved"
	case "file_renamed":
		return "File renamed"
	case "file_copied":
		return "File copied"
	case "file_restored":
		return "File restored"
	case "file_sanitized":
		return "File sanitized"
	case "folder_created":
		return "Folder created"
	case "trash_emptied":
		return "Trash emptied"
	case "versions_purged":
		return "Versions purged"
	case "recents_cleared":
		return "Recents cleared"
	case "share_sent":
		return color.CyanString("Share sent")
	case "share_received":
		return color.CyanString("Share received")
	case "share_expired":
		return color.HiBlackString("Share expired")
	case "share_rejected":
		return color.RedString("Share rejected")
	case "share_removed":
		return color.YellowString("Share removed")
	case "share_item_taken":
		return color.YellowString("Item moved out of your share")
	case "share_item_versions_dropped":
		return color.YellowString("Version history dropped")
	case "version_restored":
		return color.CyanString("Version restored")
	case "version_deleted":
		return color.YellowString("Version deleted")
	case "public_link_created":
		return color.CyanString("Link created")
	case "public_link_deleted":
		return color.YellowString("Link deleted")
	case "public_link_expired":
		return color.HiBlackString("Link expired")
	case "public_link_limit_reached":
		return color.YellowString("Link limit reached")
	case "space_invite_received":
		return color.CyanString("Space invite received")
	case "space_invite_accepted":
		return color.GreenString("Space invite accepted")
	case "space_invite_declined":
		return color.HiBlackString("Space invite declined")
	case "space_member_left":
		return color.YellowString("Member left a space")
	case "space_member_joined":
		return color.GreenString("Member joined a space")
	case "space_member_removed":
		return color.YellowString("Member removed from a space")
	case "space_role_changed":
		return color.CyanString("Space role changed")
	case "space_archived":
		return color.YellowString("Space archived")
	case "space_unarchived":
		return color.GreenString("Space reopened")
	case "space_deleted":
		return color.RedString("Space deleted")
	case "storage_warning":
		return color.YellowString("Storage warning")
	case "storage_full":
		return color.RedString("Storage full")
	case "storage_readonly":
		return color.RedString("Storage read-only")
	case "storage_purge_notice":
		return color.RedString("Final storage notice")
	case "space_stake_retained":
		return color.YellowString("Space stake held after leaving")
	case "space_stake_released":
		return color.GreenString("Space stake released")
	case "space_stake_partly_released":
		return color.GreenString("Space stake partly released")
	case "subscription_created":
		return color.GreenString("Subscription created")
	case "subscription_renewed":
		return color.GreenString("Subscription renewed")
	case "subscription_upgraded":
		return color.CyanString("Plan upgraded")
	case "subscription_downgraded":
		return color.YellowString("Plan downgraded")
	case "subscription_cancelled":
		return color.YellowString("Auto-renewal disabled")
	case "subscription_reactivated":
		return color.GreenString("Auto-renewal enabled")
	case "subscription_expired":
		return color.RedString("Subscription expired")
	case "payment_failed":
		return color.RedString("Payment failed")
	case "payment_retry_failed":
		return color.RedString("Payment retry failed")
	case "payment_final_failed":
		return color.RedString("Final payment attempt failed")
	case "payment_card_expiring":
		return color.YellowString("Card expires before renewal")
	case "subscription_term_ending":
		return color.YellowString("Prepaid year ending")
	case "payment_action_required":
		return color.YellowString("Payment action required")
	case "subscription_disputed":
		return color.RedString("Payment disputed")
	case "expansion_pack_added":
		return color.CyanString("Storage expanded")
	case "expansion_pack_removed":
		return color.YellowString("Storage expansion removed")
	case "friend_request_received":
		return color.CyanString("Friend request received")
	case "friend_request_accepted":
		return color.GreenString("Friend request accepted")
	case "friend_request_declined":
		return color.HiBlackString("Friend request declined")
	case "friend_removed_by_peer":
		return color.YellowString("Friend removed you")
	case "chat_message_received":
		return color.CyanString("New chat message")
	case "chat_message_reaction":
		return color.CyanString("New reaction")
	case "chat_message_edited":
		return color.HiBlackString("Message edited")
	case "chat_message_deleted":
		return color.HiBlackString("Message deleted")
	case "chat_group_message_received":
		return color.CyanString("New group message")
	case "chat_group_added":
		return color.CyanString("Added to a group")
	case "chat_group_removed":
		return color.YellowString("Removed from a group")
	case "chat_group_owner_promoted":
		return color.CyanString("Promoted to group owner")
	case "chat_group_message_reaction":
		return color.CyanString("New group reaction")
	case "cli_update":
		return color.CyanString("CLI update available")
	case "desktop_update":
		return color.CyanString("Desktop update available")
	case "platform_update":
		return color.CyanString("Platform update")
	case "admin_report_received":
		return color.YellowString("Abuse report received")
	default:
		return eventType
	}
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
	_, privKey := e2ee.GetKeyPair(func() {})
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
		name := entry.Name
		if entry.E2EEDisplayName != "" {
			name = e2ee.DecryptE2EEName(entry.E2EEDisplayName)
		}
		if entry.ID == "" || name == "" || name == "(encrypted)" {
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
