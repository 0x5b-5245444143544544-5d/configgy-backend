package api

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/labstack/echo/v4"
)

// jsonSerializer implements JSON encoding using encoding/json.
type jsonSerializer struct{}

// Serialize converts an interface into a json and writes it to the response.
// You can optionally use the indent parameter to produce pretty JSONs.
func (d jsonSerializer) Serialize(c echo.Context, i interface{}, indent string) error {
	enc := json.NewEncoder(c.Response())
	if indent != "" {
		enc.SetIndent("", indent)
	}
	enc.SetEscapeHTML(false)
	return enc.Encode(i)
}

// Deserialize reads a JSON from a request body and converts it into an interface.
func (d jsonSerializer) Deserialize(c echo.Context, i interface{}) error {
	err := json.NewDecoder(c.Request().Body).Decode(i)
	switch t := err.(type) {
	case *json.UnmarshalTypeError:
		return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("Unmarshal type error: expected=%v, got=%v, field=%v, offset=%v", t.Type, t.Value, t.Field, t.Offset)).SetInternal(err)
	case *json.SyntaxError:
		return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("Syntax error: offset=%v, error=%v", t.Offset, t.Error())).SetInternal(err)
	default:
		return err
	}
}
