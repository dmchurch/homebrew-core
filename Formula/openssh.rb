class Openssh < Formula
  desc "OpenBSD freely-licensed SSH connectivity tools"
  homepage "https://www.openssh.com/"
  url "https://ftp.openbsd.org/pub/OpenBSD/OpenSSH/portable/openssh-8.0p1.tar.gz"
  mirror "https://mirror.vdms.io/pub/OpenBSD/OpenSSH/portable/openssh-8.0p1.tar.gz"
  version "8.0p1"
  sha256 "bd943879e69498e8031eb6b7f44d08cdc37d59a7ab689aa0b437320c3481fd68"

  bottle do
    sha256 "205e6e27d530dea1c47423dea5f4d0197a708a8b66d82974220c39afa4862c40" => :mojave
    sha256 "5b6a4b5ab220e6e77895c7abbd2194332bfc9f8f5d973059b851bc23546aa643" => :high_sierra
    sha256 "c8d466551529ebcb1c4d17da2d389cec164c5eee45a7174325f830fbfcc6fdd6" => :sierra
  end

  # Please don't resubmit the keychain patch option. It will never be accepted.
  # https://github.com/Homebrew/homebrew-dupes/pull/482#issuecomment-118994372

  depends_on "pkg-config" => :build
  depends_on "ldns"
  depends_on "openssl"

  resource "com.openssh.sshd.sb" do
    url "https://opensource.apple.com/source/OpenSSH/OpenSSH-209.50.1/com.openssh.sshd.sb"
    sha256 "a273f86360ea5da3910cfa4c118be931d10904267605cdd4b2055ced3a829774"
  end

  # Both these patches are applied by Apple.
  patch do
    url "https://raw.githubusercontent.com/Homebrew/patches/1860b0a74/openssh/patch-sandbox-darwin.c-apple-sandbox-named-external.diff"
    sha256 "d886b98f99fd27e3157b02b5b57f3fb49f43fd33806195970d4567f12be66e71"
  end

  patch do
    url "https://raw.githubusercontent.com/Homebrew/patches/d8b2d8c2/openssh/patch-sshd.c-apple-sandbox-named-external.diff"
    sha256 "3505c58bf1e584c8af92d916fe5f3f1899a6b15cc64a00ddece1dc0874b2f78f"
  end

  # More patches from Apple.
  patch do
    url "https://raw.githubusercontent.com/dmchurch/formula-patches/openssh-apple-support/openssh/patch-audit-bsm.c-apple-audit-support.diff"
    sha256 "bc9858980b81a1c3b6d7200f08b527aa960c2f9685e26ba46cfe7b07212aef37"
  end

  patch do
    url "https://raw.githubusercontent.com/dmchurch/formula-patches/openssh-apple-support/openssh/patch-clientloop.c-apple-launchd-display-variable.diff"
    sha256 "cd157fa5b0d8f66106d80686cedff6857720a4073f8d1bfb6d71bd8709472f5c"
  end

  patch do
    url "https://raw.githubusercontent.com/dmchurch/formula-patches/openssh-apple-support/openssh/patch-groupaccess.c-apple-group-support.diff"
    sha256 "c825bd95573d67889a0f0e748ae7359c85a5c211fb2a9fd63a50c001caefb8fd"
  end

  patch do
    url "https://raw.githubusercontent.com/dmchurch/formula-patches/openssh-apple-support/openssh/patch-session.c-apple-tmpdir-support.diff"
    sha256 "0aead1becfd3293245d684cf11195ed52383e5b86c1ff321d09c8602d1c4a1ca"
  end

  patch do
    url "https://raw.githubusercontent.com/dmchurch/formula-patches/openssh-apple-support/openssh/patch-ssh-agent.c-launchd-support.diff"
    sha256 "cb2f50c13eb7076545d41590df441cf4208d558da47176315bd60baa5f0a171f"
  end

  # Add PKCS#11 label support until merged upstream
  patch do
    url "https://patch-diff.githubusercontent.com/raw/openssh/openssh-portable/pull/138.diff"
    sha256 "d49fa45c434fa8d44c79cb8f5509a213e5730d2a5f5a9591af946b71b6d1b1b7"
  end

  def install
    ENV.append "CPPFLAGS", "-D__APPLE_SANDBOX_NAMED_EXTERNAL__"
    ENV.append "CPPFLAGS", "-D__APPLE_DISPLAY_VAR__"
    ENV.append "CPPFLAGS", "-D__APPLE_MEMBERSHIP__"
    ENV.append "CPPFLAGS", "-D__APPLE_TMPDIR__"
    ENV.append "CPPFLAGS", "-D__APPLE_LAUNCHD__"

    # Ensure sandbox profile prefix is correct.
    # We introduce this issue with patching, it's not an upstream bug.
    inreplace "sandbox-darwin.c", "@PREFIX@/share/openssh", etc/"ssh"

    args = %W[
      --prefix=#{prefix}
      --sysconfdir=#{etc}/ssh
      --with-ldns
      --with-libedit
      --with-kerberos5
      --with-pam
      --with-ssl-dir=#{Formula["openssl"].opt_prefix}
    ]

    system "./configure", *args
    system "make"
    ENV.deparallelize
    system "make", "install"

    # This was removed by upstream with very little announcement and has
    # potential to break scripts, so recreate it for now.
    # Debian have done the same thing.
    bin.install_symlink bin/"ssh" => "slogin"

    buildpath.install resource("com.openssh.sshd.sb")
    (etc/"ssh").install "com.openssh.sshd.sb" => "org.openssh.sshd.sb"
  end

  test do
    assert_match "OpenSSH_", shell_output("#{bin}/ssh -V 2>&1")

    begin
      pid = fork { exec sbin/"sshd", "-D", "-p", "8022" }
      sleep 2
      assert_match "sshd", shell_output("lsof -i :8022")
    ensure
      Process.kill(9, pid)
      Process.wait(pid)
    end
  end
end
