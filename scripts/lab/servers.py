"""Toy network services for the ENG-14 lab: a real SMTP server (Python's smtpd protocol engine) that knows a few mailboxes and
answers VRFY/EXPN/RCPT like a real MTA (252/550), and a distcc daemon stand-in that speaks the distcc wire protocol far enough
to answer a job. The CLIENT traffic (nmap NSE scripts, smtplib) is real; only the servers are small."""
import asyncore
import smtpd
import socketserver
import threading
import warnings

warnings.filterwarnings("ignore")
MAILBOXES = {"root", "postmaster", "admin", "alice", "bob", "mail", "www-data", "ops"}


class Channel(smtpd.SMTPChannel):
    def smtp_VRFY(self, arg):
        user = arg.strip().strip("<>").split("@")[0].lower()
        self.push("252 2.0.0 %s" % arg if user in MAILBOXES else "550 5.1.1 <%s>: Recipient address rejected: User unknown" % user)

    def smtp_EXPN(self, arg):
        self.push("502 5.5.1 EXPN not supported")

    def smtp_RCPT(self, arg):
        addr = arg[3:].strip().strip("<>").split("@")[0].lower() if arg.upper().startswith("TO:") else ""
        if addr in MAILBOXES:
            return super().smtp_RCPT(arg)
        self.push("550 5.1.1 <%s>: Recipient address rejected: User unknown in local recipient table" % addr)


class Server(smtpd.SMTPServer):
    channel_class = Channel

    def process_message(self, *a, **k):
        return None


class Distcc(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(5)
        try:
            data = self.request.recv(65536)
            if data.startswith(b"DIST"):
                self.request.sendall(b"DONE00000001STAT00000000SERR00000000SOUT00000000DOTI00000000")
        except OSError:
            pass


class TS(socketserver.ThreadingTCPServer):
    allow_reuse_address = True


if __name__ == "__main__":
    Server(("0.0.0.0", 25), None, decode_data=False)
    t = TS(("0.0.0.0", 3632), Distcc)
    threading.Thread(target=t.serve_forever, daemon=True).start()
    print("smtp:25 distcc:3632 up", flush=True)
    asyncore.loop()
