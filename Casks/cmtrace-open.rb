cask "cmtrace-open" do
  version "1.6.0"
  sha256 "e0a5b55d64bf5d0c5aa2e62fad4aced7ee95865f89683a3cbd8fe4a8bcbe1ac1"

  url "https://github.com/adamgell/cmtraceopen/releases/download/v#{version}/CMTrace.Open_#{version}_aarch64.dmg",
      verified: "github.com/adamgell/cmtraceopen/"
  name "CMTrace Open"
  desc "Log viewer for ConfigMgr, Intune, and Windows diagnostic logs"
  homepage "https://cmtraceopen.com/"

  livecheck do
    url :url
    strategy :github_latest
  end

  depends_on arch: :arm64
  depends_on :macos

  app "CMTrace Open.app"

  zap trash: [
    "~/Library/Application Support/com.cmtrace.open",
    "~/Library/Caches/com.cmtrace.open",
    "~/Library/Logs/com.cmtrace.open",
    "~/Library/Preferences/com.cmtrace.open.plist",
    "~/Library/WebKit/com.cmtrace.open",
  ]
end
