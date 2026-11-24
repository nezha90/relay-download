package protocol

import (
	"encoding/json"
	"io"
	"net/http"
)

func WriteJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func WriteError(w http.ResponseWriter, status int, msg string) {
	WriteJSON(w, status, ErrorResp{Error: msg})
}

func DecodeJSON(r io.Reader, dst any) error {
	dec := json.NewDecoder(io.LimitReader(r, 4*1024*1024))
	return dec.Decode(dst)
}
