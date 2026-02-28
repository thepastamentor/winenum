from dataclasses import dataclass
from typing import Optional

@dataclass
class Target:
    ip: str
    username: Optional[str] = None
    password: Optional[str] = None
    domain: Optional[str] = None
    hash: Optional[str] = None
    
    def has_creds(self) -> bool:
        return bool(self.username and (self.password or self.hash))
    
    def cred_string(self) -> str:
        if not self.username:
            return "anonymous"
        domain = f"{self.domain}\\" if self.domain else ""
        return f"{domain}{self.username}"
    
    def netexec_auth(self) -> list:
        """Return netexec auth arguments"""
        cmd = []
        if self.domain:
            cmd.extend(['-d', self.domain])
        if self.username:
            cmd.extend(['-u', self.username])
            if self.hash:
                cmd.extend(['-H', self.hash])
            elif self.password:
                cmd.extend(['-p', self.password])
        return cmd
    
    def impacket_target(self) -> str:
        """Return impacket-style target string"""
        if self.domain:
            return f'{self.domain}/{self.username}'
        return self.username or ''
