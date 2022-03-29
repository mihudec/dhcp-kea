import ipaddress
from optparse import Option
import pathlib
import json
from functools import lru_cache
from pydantic import BaseModel, Extra, Field, root_validator, validator
from pydantic.typing import Optional, List, Dict, Literal
from pydantic.types import NonNegativeInt, PositiveInt


@lru_cache(maxsize=256)
def kea_alias_generator(k: str):
    exception_map = {
        'output_options': 'output_options'
    }
    if k in exception_map.keys():
        return exception_map[k]
    else:
        return k.replace('_', '-')


def get_dhcp_options():
    options_file = pathlib.Path(__file__).resolve().parent.joinpath('dhcp_options.json')
    dhcp_options = json.loads(options_file.read_text())
    return dhcp_options

class BaseKeaModel(BaseModel):

    class Config:
        extra_config: Extra.allow
        alias_generator = kea_alias_generator
        anystr_strip_whitespace = True
        validate_assignment = True
        allow_population_by_field_name = True


class KeaLoggerOutput(BaseKeaModel):

    output: pathlib.Path = Field(description="Path to the logfile")
    pattern: Optional[str]
    flush: Optional[bool] = Field(default=False, description="This governs whether the log output is flushed to disk after every write")
    maxsize: Optional[PositiveInt]
    maxver: Optional[PositiveInt]


class KeaLogger(BaseKeaModel):

    name: str
    output_options: List[KeaLoggerOutput]
    severity: str
    debuglevel: NonNegativeInt = Field(default=0)

    @classmethod
    def get_default_dhcp4(cls) -> List['KeaLogger']:
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

    socket_type: Literal['unix'] = Field(default='unix')
    socket_name: pathlib.Path

    @classmethod
    def get_default_kea4(cls):
        return cls(
            socket_name='/tmp/kea4-ctrl-socket'
        )


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


class KeaDhcpOptionBase(BaseKeaModel):

    name: Optional[str]
    code: Optional[NonNegativeInt]
    space: Optional[str]


class KeaDhcpOptionDef(KeaDhcpOptionBase):
    
    array: Optional[bool]
    encapsulation: Optional[str]
    record_types: Optional[str]
    type: str


class KeaDhcpOption(KeaDhcpOptionBase):

    data: Optional[str]
    always_send: Optional[bool]
    csv_format: Optional[bool]

    @root_validator(allow_reuse=True)
    def validate_code_or_name(cls, values):
        if not any([values.get(x) for x in ['name', 'code']]):
            raise AssertionError("Either 'name' or 'code' must be set.")
        else:
            return values


class KeaDhcpClientClass(BaseKeaModel):

    name: str
    test: str
    option_data: Optional[List[KeaDhcpOption]]
    option_def: Optional[List[KeaDhcpOptionDef]]



class KeaClient4Reservation(BaseKeaModel):

    client_id: Optional[str]
    circuit_id: Optional[str]
    hw_address: Optional[str]
    hostname: Optional[str]
    ip_address: Optional[ipaddress.IPv4Address]
    option_data: Optional[List[KeaDhcpOption]]
    option_def: Optional[List[KeaDhcpOptionDef]]

class KeaRelay4(BaseKeaModel):

    ip_addresses: List[ipaddress.IPv4Address]

class KeaPoolCommon(BaseKeaModel):
    
    option_data: Optional[List[KeaDhcpOption]]
    option_def: Optional[List[KeaDhcpOptionDef]]
    
    server_hostname: Optional[str]

    client_class: Optional[str]
    require_client_classes: Optional[List[str]]
    user_context: Optional[dict]


class KeaPool4(KeaPoolCommon):

    pool: str

    @validator('pool', pre=True, allow_reuse=True)
    def validate_pool(cls, v):
        if isinstance(v, list):
            addresses = []
            if len(v) > 2 or len(v) < 1:
                raise AssertionError('Pool list must have length 0 < len(pool) <= 2')
            try: 
                addresses = [ipaddress.IPv4Address(x) for x in v]
            except Exception as e:
                raise AssertionError("Pool entries must be valid IPv4 addresses")
            if len(addresses) == 1:
                v = " - ".join([str(x) for x in [addresses[0]]*2])
            elif len(addresses) == 2:
                v = " - ".join([str(x) for x in addresses])
            else:
                raise Exception("Undetermined state")
        elif isinstance(v, str):
            v = cls.validate_pool(v=[x.strip() for x in v.split('-')])
        return v


class KeaSubnet4(KeaPoolCommon):

    authoritative: Optional[bool]
    subnet: ipaddress.IPv4Network
    pools: Optional[List[KeaPool4]]
    min_valid_lifetime: Optional[NonNegativeInt]
    valid_lifetime: Optional[NonNegativeInt]
    max_valid_lifetime: Optional[NonNegativeInt]
    
    renew_timer: Optional[NonNegativeInt]
    rebind_timer: Optional[NonNegativeInt]
    
    relay: Optional[KeaRelay4]
    interface: Optional[str]
    reservations: Optional[List[KeaClient4Reservation]]


class KeaInterfacesConfig(BaseKeaModel):

    interfaces: Optional[List[str]]
    dhcp_socket_type: Optional[Literal['raw', 'udp']]
    outbound_interface: Optional[Literal['use-routing', 'same-as-inbound']] = Field(default='same-as-inbound')
    re_detect: Optional[bool] = Field(default=True)


class KeaSanityChecks(BaseKeaModel):

    lease_checks: Optional[Literal['none', 'warn', 'fix', 'fix-del', 'del']] = Field(default='fix-del')



class KeaDhcp4Config(KeaBaseConfigContainer):

    authoritative: Optional[bool]
    interfaces_config: Optional[KeaInterfacesConfig]
    sanity_checks: Optional[KeaSanityChecks]
    lease_database: Optional[KeaLeaseDatabase] = Field(default_factory=KeaLeaseDatabase)
    control_socket: KeaControlSocket = Field(default_factory=KeaControlSocket.get_default_kea4)
    expired_leases_processing: Optional[KeaExpiredLeasesProcessing] = Field(default_factory=KeaExpiredLeasesProcessing)
    
    min_valid_lifetime: Optional[NonNegativeInt]
    valid_lifetime: Optional[NonNegativeInt] = Field(default=3600)
    max_valid_lifetime: Optional[NonNegativeInt]

    renew_timer: Optional[NonNegativeInt]
    rebind_timer: Optional[NonNegativeInt]
    
    option_data: Optional[List[KeaDhcpOption]]
    option_def: Optional[List[KeaDhcpOptionDef]]
    client_classes: Optional[List[KeaDhcpClientClass]]
    server_hostname: Optional[str]
    subnet4: Optional[List[KeaSubnet4]]
    loggers: Optional[List[KeaLogger]] = Field(default_factory=KeaLogger.get_default_dhcp4)


class KeaConfigFileDhcp4(BaseKeaModel):
    
    Dhcp4: KeaDhcp4Config


class KeaFilters:

    def get_kea4_config(self, data: dict):
        dhcp4 = KeaDhcp4Config.parse_obj(data)
        return KeaConfigFileDhcp4(Dhcp4=dhcp4).json(by_alias=True, indent=2, sort_keys=True, exclude_none=True)

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
