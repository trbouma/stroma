from stroma import Keys, fips_ipv6_address

PUBLIC_HEX = "4f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa"
PUBLIC_NPUB = (
    "npub1fu64hh9hes90w2808n8tjc2ajp5yhddjef0ctx4s7zmsgp6cwx4qgy4eg9"
)
FIPS_IPV6 = "fd34:da5e:3969:3577:9c48:835a:7f60:8b56"


def test_fips_ipv6_address_matches_public_key_derivation() -> None:
    assert fips_ipv6_address(PUBLIC_HEX) == FIPS_IPV6
    assert fips_ipv6_address(PUBLIC_NPUB) == FIPS_IPV6
    assert fips_ipv6_address(Keys(pub_k=PUBLIC_NPUB)) == FIPS_IPV6
