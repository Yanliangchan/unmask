"""Product identity: the name, descriptor and tagline, in one place.

Technical identifiers (``UNMASK_*`` settings, cookie names, the package) are
not branding and stay as they are.
"""

NAME = "UNMASK"
DESCRIPTOR = "OSINT case platform"
TAGLINE = "Authorise. Evidence. Report."
SHORT_PITCH = (
    "Run your OSINT tools as one authorised case on your own servers, and hand over a report with the method "
    "and the evidence attached."
)
DESCRIPTION = (
    "UNMASK is an open-source, self-hosted case platform for authorised OSINT investigations. It runs your tools "
    "as one case: findings are de-duplicated, scored with their reasons, linked and compared between scans, and "
    "every step is on the record."
)
# Where the code lives, for "Self-host it" and the footer. Make the repository public before linking to it.
SOURCE_URL = "https://github.com/Yanliangchan/unmask"
LICENCE = "MIT"
THEME_LIGHT = "#F5F6F8"
THEME_DARK = "#0B0D12"
