package keycloak

import "testing"

func Test_getIdFromLocationHeader(t *testing.T) {
	type args struct {
		locationHeader string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "success",
			args: args{
				locationHeader: "http://localhost:8081/admin/realms/xamax/webhooks/9e2e0b52-a485-44ee-b623-6e19443fe3c2",
			},
			want: "9e2e0b52-a485-44ee-b623-6e19443fe3c2",
		}, {
			name: "success 2",
			args: args{
				locationHeader: "http://localhost:8081/admin/realms/xamax/webhooks/",
			},
			want: "",
		}, {
			name: "success 3",
			args: args{
				locationHeader: "http://localhost:8081/admin/realms/xamax/webhooks",
			},
			want: "webhooks",
		}, {
			name: "success 3",
			args: args{
				locationHeader: "webhooks",
			},
			want: "webhooks",
		}, {
			name: "success 4",
			args: args{
				locationHeader: "",
			},
			want: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := getIdFromLocationHeader(tt.args.locationHeader); got != tt.want {
				t.Errorf("getIdFromLocationHeader() = %v, want %v", got, tt.want)
			}
		})
	}
}
