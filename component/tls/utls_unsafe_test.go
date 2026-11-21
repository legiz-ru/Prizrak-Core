package tls

import (
	"context"
	"reflect"
	"testing"
	"unsafe"

	"github.com/metacubex/tls"
	utls "github.com/metacubex/utls"
)

func TestUTLSPrivateFieldLayouts(t *testing.T) {
	contextType := reflect.TypeOf((*context.Context)(nil)).Elem()
	keyingMaterialType := reflect.TypeOf((func(string, []byte, int) ([]byte, error))(nil))
	fields := []struct {
		name  string
		typ   reflect.Type
		field string
		want  reflect.Type
	}{
		{"crypto/tls.CertificateRequestInfo", reflect.TypeOf(tls.CertificateRequestInfo{}), "ctx", contextType},
		{"uTLS.CertificateRequestInfo", reflect.TypeOf(utls.CertificateRequestInfo{}), "ctx", contextType},
		{"crypto/tls.ClientHelloInfo", reflect.TypeOf(tls.ClientHelloInfo{}), "ctx", contextType},
		{"uTLS.ClientHelloInfo", reflect.TypeOf(utls.ClientHelloInfo{}), "ctx", contextType},
		{"crypto/tls.ConnectionState", reflect.TypeOf(tls.ConnectionState{}), "ekm", keyingMaterialType},
		{"uTLS.ConnectionState", reflect.TypeOf(utls.ConnectionState{}), "ekm", keyingMaterialType},
	}

	for _, test := range fields {
		t.Run(test.name+"/"+test.field, func(t *testing.T) {
			field, ok := test.typ.FieldByName(test.field)
			if !ok {
				t.Fatalf("field %s is missing", test.field)
			}
			if field.Type != test.want {
				t.Fatalf("field %s type = %v, want %v", test.field, field.Type, test.want)
			}
			if field.Offset+field.Type.Size() > test.typ.Size() {
				t.Fatalf("field %s offset %d with size %d exceeds struct size %d", test.field, field.Offset, field.Type.Size(), test.typ.Size())
			}
			if got := mustUnsafeFieldOffset(test.typ, test.field, test.want); got != field.Offset {
				t.Fatalf("validated field offset = %d, want %d", got, field.Offset)
			}
		})
	}
}

func TestMustUnsafeFieldOffsetRejectsTypeMismatch(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("mustUnsafeFieldOffset accepted a field with the wrong type")
		}
	}()
	mustUnsafeFieldOffset(reflect.TypeOf(struct{ field int }{}), "field", reflect.TypeOf(""))
}

func TestTLSConnectionStatePreservesExportKeyingMaterial(t *testing.T) {
	const want = "exported"
	state := utls.ConnectionState{}
	field, ok := reflect.TypeOf(state).FieldByName("ekm")
	if !ok {
		t.Fatal("uTLS ConnectionState.ekm is missing")
	}
	*(*func(string, []byte, int) ([]byte, error))(unsafe.Add(unsafe.Pointer(&state), field.Offset)) = func(_ string, _ []byte, length int) ([]byte, error) {
		result := make([]byte, length)
		copy(result, want)
		return result, nil
	}

	converted := tlsConnectionState(state)
	got, err := converted.ExportKeyingMaterial("test", nil, len(want))
	if err != nil {
		t.Fatalf("ExportKeyingMaterial returned an error: %v", err)
	}
	if string(got) != want {
		t.Fatalf("ExportKeyingMaterial = %q, want %q", got, want)
	}
}
