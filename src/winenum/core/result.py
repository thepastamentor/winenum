from dataclasses import dataclass, field

@dataclass
class ServiceResult:
    service: str
    port: int
    open: bool = False
    anonymous_access: bool = False
    guest_access: bool = False
    cred_access: bool = False
    details: dict = field(default_factory=dict)
    errors: list = field(default_factory=list)
