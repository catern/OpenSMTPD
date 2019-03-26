{ pkgs ? (import <nixpkgs> {}) }:

pkgs.opensmtpd.overrideAttrs (_: { src = ./.; })
