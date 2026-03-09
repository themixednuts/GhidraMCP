set shell := ["bash", "-euo", "pipefail", "-c"]
set windows-shell := ["powershell.exe", "-NoLogo", "-NoProfile", "-Command"]

gradlew := if os_family() == "windows" { ".\\gradlew.bat" } else { "bash ./gradlew" }
gradlew_e2e := if os_family() == "windows" { ".\\gradlew.bat --%" } else { "bash ./gradlew" }

default:
  just --list

install-hooks:
  git config core.hooksPath .githooks

ci:
  {{gradlew}} ci

bootstrap:
  {{gradlew}} bootstrap

bootstrap-latest:
  {{gradlew}} bootstrapGhidra -PghidraRelease=latest

build:
  {{gradlew}} build

package:
  {{gradlew}} package

test:
  {{gradlew}} test

test-e2e:
  {{gradlew_e2e}} test -De2e.integration=true

fmt:
  {{gradlew}} spotlessApply

fmt-check:
  {{gradlew}} spotlessCheck

fmt-build:
  {{gradlew}} spotlessMiscApply

fmt-build-check:
  {{gradlew}} spotlessMiscCheck

clean:
  {{gradlew}} clean

versions:
  {{gradlew}} printGhidraVersion printMcpBomVersion
