# Homebrew formula template for secure-vibe.
#
# This file is the canonical source for the shieldnet-360/tap/secure-vibe formula.
# On release, the "Stamp Homebrew formula" step in .github/workflows/release.yml
# fills the version + per-arch sha256 placeholders below from the binaries built
# for the new tag (the url lines interpolate v#{version}), and publishes the
# stamped result as the `secure-vibe.rb` asset on the GitHub Release. To update
# the tap, the release manager copies that published asset into the
# shieldnet-360/homebrew-tap repository (a tap-token-gated push step can automate
# this once the tap repo + secret exist).
class Securevibe < Formula
  desc "Skills Library CLI for AI-assisted coding tools"
  homepage "https://github.com/shieldnet-360/secure-vibe"
  version "0.0.0"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/shieldnet-360/secure-vibe/releases/download/v#{version}/secure-vibe-darwin-arm64"
      sha256 "REPLACE_WITH_DARWIN_ARM64_SHA256"
    end
    on_intel do
      url "https://github.com/shieldnet-360/secure-vibe/releases/download/v#{version}/secure-vibe-darwin-amd64"
      sha256 "REPLACE_WITH_DARWIN_AMD64_SHA256"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/shieldnet-360/secure-vibe/releases/download/v#{version}/secure-vibe-linux-arm64"
      sha256 "REPLACE_WITH_LINUX_ARM64_SHA256"
    end
    on_intel do
      url "https://github.com/shieldnet-360/secure-vibe/releases/download/v#{version}/secure-vibe-linux-amd64"
      sha256 "REPLACE_WITH_LINUX_AMD64_SHA256"
    end
  end

  def install
    binary = Dir["secure-vibe-*"].first
    bin.install binary => "secure-vibe"
  end

  test do
    assert_match "secure-vibe", shell_output("#{bin}/secure-vibe version")
  end
end
