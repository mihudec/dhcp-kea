import ipaddress
from pydantic import BaseModel, Extra, Field, conint, root_validator
from pydantic.typing import Optional, List, Dict
from pydantic.types import NonNegativeInt



class BaseKeaModel(BaseModel):

    class Config:
        extra_config: Extra.allow
        alias_generator = lambda x: x.replace('_', '-')
        anystr_strip_whitespace = True
        validate_assignment = True
        allow_population_by_field_name = True

class KeaLoggerOutput(BaseKeaModel):

    output: str

class KeaLogger(BaseKeaModel):

    name: str
    output_options: List[KeaLoggerOutput]
    severity: str
    debuglevel: NonNegativeInt = Field(default=0)

    @classmethod
    def default_dhcp4(cls) -> List['KeaLogger']:
        return [
            cls(
                name="kea-dhcp4",
                output_options=[
                    KeaLoggerOutput(
                        output='/var/log/kea/kea-dhcp4.log'
                    )
                ],
                severity="INFO",
                debuglevel=0
            )
        ]

class KeaControlSocket(BaseKeaModel):
    socket_type: str = Field(default='unix')
    socket_name: str = Field(default="/tmp/kea-dhcp4-ctrl.sock")

class KeaBaseConfigContainer(BaseKeaModel):

    pass


class KeaLeaseDatabase(BaseKeaModel):

    type: Optional[str] = Field(default='memfile')
    lfc_interval: Optional[NonNegativeInt] = Field(default=3600)

class KeaExpiredLeasesProcessing(BaseKeaModel):
        reclaim_timer_wait_time: Optional[NonNegativeInt] = Field(default=10)
        flush_reclaimed_timer_wait_time: Optional[NonNegativeInt] = Field(default=25)
        hold_reclaimed_time: Optional[NonNegativeInt] = Field(default=3600)
        max_reclaim_leases: Optional[NonNegativeInt] = Field(default=100)
        max_reclaim_time: Optional[NonNegativeInt] = Field(default=250)
        unwarned_reclaim_cycles: Optional[NonNegativeInt] = Field(default=5)

class KeaDhcpOption(BaseKeaModel):

    name: Optional[str]
    code: Optional[NonNegativeInt]
    data: str

    @root_validator(allow_reuse=True)
    def validate_code_or_name(cls, values):
        if not any([values.get(x) for x in ['name', 'code']]):
            raise AssertionError("Either 'name' or 'code' must be set.")
        elif all([values.get(x) for x in ['name', 'code']]):
            raise AssertionError("Either 'name' or 'code' must be set, not both.")
        else: 
            return values


class KeaDhcpClientClass(BaseKeaModel):

    name: str
    test: str


class KeaClient4Reservation(BaseKeaModel):
    client_id: Optional[str]
    hw_address: Optional[str]
    hostname: Optional[str]
    ip_address: Optional[ipaddress.IPv4Address]
    option_data: Optional[List[KeaDhcpOption]] = Field(default_factory=list)


class KeaPoolCommon(BaseKeaModel):
    
    option_data: Optional[List[KeaDhcpOption]] = Field(default_factory=list)

class KeaPool4(KeaPoolCommon):

    pool: str

class KeaSubnet4(KeaPoolCommon):

    subnet: ipaddress.IPv4Network
    pools: Optional[List[KeaPool4]] = Field(default_factory=list)
    
    reservations: Optional[List[KeaClient4Reservation]] = Field(default_factory=list)


class KeaDhcp4Config(KeaBaseConfigContainer):

    interfaces_config: Optional[List[str]] = Field(default_factory=list)
    lease_database: Optional[KeaLeaseDatabase] = Field(default_factory=KeaLeaseDatabase)
    expired_leases_processing: Optional[KeaExpiredLeasesProcessing] = Field(default_factory=KeaExpiredLeasesProcessing)
    renew_timer: Optional[NonNegativeInt] = Field(default=900)
    rebind_timer: Optional[NonNegativeInt] = Field(default=1800)
    valid_lifetime: Optional[NonNegativeInt] = Field(default=3600)
    option_data: Optional[List[KeaDhcpOption]] = Field(default_factory=list)
    client_classes: Optional[List[KeaDhcpClientClass]] = Field(default_factory=list)
    subnet4: Optional[List[KeaSubnet4]] = Field(default_factory=list)
    loggers: Optional[List[KeaLogger]] = Field(default_factory=KeaLogger.default_dhcp4)


class KeaConfigFileDhcp4(BaseKeaModel):
    
    Dhcp4: KeaDhcp4Config

class KeaFilters:

    def filters(self):
        filters = {}
        for name, method in self.__class__.__dict__.items():
            if not name.startswith("_") and callable(method):
                filters[name] = getattr(self, name)
        del filters["filters"]
        return filters



class FilterModule(object):

    def filters(self):
        return {k: v for k, v in KeaFilters().filters().items()}


if __name__ == '__main__':

    print(KeaConfigFileDhcp4(Dhcp4=KeaDhcp4Config()).json(by_alias=True, indent=2, sort_keys=True))