// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

# Documentation available at: https://docs.docker.com/build/bake/

variable "IMAGE_REPO" { default = "ghcr.io/agntcy" }
variable "IMAGE_TAG" { default = "v0.1.0-rc" }
variable "BUILD_LDFLAGS" { default = "-s -w -extldflags -static" }
variable "IMAGE_NAME_SUFFIX" { default = "" }

function "get_tag" {
  params = [tags, name]
  result = coalescelist(tags, ["${IMAGE_REPO}/${name}${IMAGE_NAME_SUFFIX}:${IMAGE_TAG}"])
}

group "default" {
  targets = [
    "oidc-gateway",
  ]
}

target "_common" {
  output = [
    "type=image",
  ]
  platforms = [
    "linux/arm64",
    "linux/amd64",
  ]
  args = {
    BUILD_LDFLAGS = "${BUILD_LDFLAGS}"
  }
}

target "docker-metadata-action" {
  tags = []
}

target "oidc-gateway" {
  context    = "."
  dockerfile = "./cmd/oidc-gateway/Dockerfile"
  inherits = [
    "_common",
    "docker-metadata-action",
  ]
  tags = get_tag(target.docker-metadata-action.tags, "${target.oidc-gateway.name}")
}
