cask "cmtrace-open" do
  version "1.6.2"
  sha256 "ba9dd76823612370c58ad6881e4da6efd826ac565f63e5701b334f6bca84b02e"

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
