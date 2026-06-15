module github.com/agntcy/oidc-gateway/authzserver

go 1.26.3

require (
	github.com/agntcy/oidc-gateway/identity v1.1.1
	github.com/casbin/casbin/v2 v2.135.0
	github.com/envoyproxy/go-control-plane/envoy v1.37.0
	golang.org/x/net v0.56.0
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260526163538-3dc84a4a5aaa
	google.golang.org/grpc v1.81.1
	google.golang.org/protobuf v1.36.11
)

replace github.com/agntcy/oidc-gateway/identity => ../identity

require (
	github.com/bmatcuk/doublestar/v4 v4.10.0 // indirect
	github.com/casbin/govaluate v1.10.0 // indirect
	github.com/cncf/xds/go v0.0.0-20260202195803-dba9d589def2 // indirect
	github.com/envoyproxy/protoc-gen-validate v1.3.3 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/planetscale/vtprotobuf v0.6.1-0.20240319094008-0393e58bdf10 // indirect
	golang.org/x/sys v0.46.0 // indirect
	golang.org/x/text v0.38.0 // indirect
)
