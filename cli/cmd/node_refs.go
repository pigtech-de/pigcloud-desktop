package cmd

import (
	"context"
	"encoding/json"

	"pigcloud/internal/cmdutil"
	"pigcloud/internal/e2ee"
	"pigcloud/internal/output"
)

func writerParentKey() []byte {
	if !e2ee.HasE2EEKeys() {
		return nil
	}
	key := cmdutil.GetParentKey(ExitWithError)
	if len(key) == 0 {
		refuseWrite(e2ee.ErrParentKeyUnavailable)
	}
	return key
}

func refuseWrite(err error) {
	output.PrintError(err.Error())
	ExitWithError()
}

func mintInto(parentID string, parentKey []byte) func(map[string]string) error {
	return func(options map[string]string) error {
		ref, err := e2ee.MintSealedNode(parentID, parentKey)
		if err != nil {
			return err
		}
		e2ee.AddNodeRef(options, ref)
		return nil
	}
}

func sealNewNode(ctx context.Context, options map[string]string, parentPath string, parentKey []byte) func(map[string]string) error {
	if parentKey == nil {
		return nil
	}
	parentID, err := cmdutil.ResolveDirID(ctx, parentPath)
	if err != nil {
		refuseWrite(err)
		return nil
	}
	mint := mintInto(parentID, parentKey)
	if err := mint(options); err != nil {
		refuseWrite(err)
		return nil
	}
	return mint
}

func ensureFolderChain[T any](ctx context.Context, remotePath string, parentKey []byte) (e2ee.FolderChain, T) {
	var payload T
	chain, err := e2ee.EnsureFolderChain(ctx, cmdutil.RefExecutor(), remotePath, parentKey)
	if err != nil {
		refuseWrite(err)
		return chain, payload
	}
	if chain.Resp == nil || !chain.Resp.Success {
		msg := "the server declined to create " + remotePath
		if chain.Resp != nil && chain.Resp.Message != "" {
			msg = chain.Resp.Message
		}
		output.PrintError(msg)
		ExitWithError()
		return chain, payload
	}
	if err := json.Unmarshal(chain.Resp.Raw, &payload); err != nil {
		output.PrintError("Failed to parse response: " + err.Error())
		ExitWithError()
	}
	return chain, payload
}
