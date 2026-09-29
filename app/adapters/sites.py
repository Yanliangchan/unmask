"""The focused site lists for username tools.

Sherlock knows ~480 sites and Maigret ~5,900. Most of the long tail is small
forums and regional sites whose "user exists" checks break often; they add
minutes to every scan and most of the false positives. The focused lists keep
the sites where people actually have profiles and whose checks hold up:
mainstream social, developer, creative, gaming and professional sites.

Names must match each tool's own site names exactly; they were checked
against Sherlock 0.15 and Maigret 0.5. Set UNMASK_USERNAME_SITES=all to go
back to the full lists.
"""

SHERLOCK_FOCUSED = """
About.me|Academia.edu|ArtStation|Bandcamp|Behance|BitBucket|Blogger|Bluesky|BugCrowd|BuyMeACoffee|Carrd|Chess|
Codeberg|Codecademy|Codeforces|Codepen|Coderwall|Codewars|Crowdin|Cults3D|DEV Community|DeviantArt|Discogs|Disqus|
Docker Hub|Dribbble|Duolingo|Fandom|Flickr|Flipboard|Freelancer|Freesound|Genius (Artists)|Giphy|GitHub|GitLab|Gitea|
Gitee|GoodReads|Grailed|Gravatar|HackTheBox|Hackaday|HackerEarth|HackerNews|HackerOne|HackerRank|Hashnode|Houzz|Imgur|
Instagram|Instructables|Itch.io|Kaggle|Keybase|Kick|Launchpad|LeetCode|Letterboxd|Lichess|Linktree|Lobsters|Medium|
Minecraft|MixCloud|Myspace|Pastebin|Patreon|Pinterest|ProductHunt|PyPi|Redbubble|Reddit|Replit.com|ResearchGate|
Roblox|Scribd|Slashdot|Slides|Smule|Snapchat|SoundCloud|SourceForge|Speedrun.com|Spotify|Steam Community (User)|
Strava|Substack|Telegram|Tellonym.me|TikTok|Trakt|Trello|TryHackMe|Twitch|Twitter|Unsplash|VK|VSCO|Venmo|Vimeo|
Wattpad|Weblate|Weebly|Wikipedia|Wix|WordPress|WordPressOrg|Xbox Gamertag|YouTube|kofi|last.fm|mastodon.social|npm|
osu!|threads|tumblr
"""

MAIGRET_FOCUSED = """
500px|About.me|Academia.edu|Artstation|AskFM|Bandcamp|Behance|BitBucket|Blogger|Bluesky|Bugcrowd|BuyMeACoffee|Chess|
Codecademy|Codepen|Coderwall|Codewars|Crowdin|Cults3d|DEV Community|Depop|DeviantART|Discogs|Disqus|Docker Hub|
Dribbble|Duolingo|Ebay|Etsy|Facebook|Fandom|Fiverr|Flickr|Flipboard|Freesound|Giphy|GitHub|GitLab|Gitea|Gitee|
GoodReads|Grailed|Gravatar|HackTheBox|Hackaday|HackerNews|HackerOne|Hackerearth|Hackerrank|Hashnode|Houzz|Imgur|
Instagram|Instructables|Itch.io|Kaggle|Keybase|Kick|Launchpad|LeetCode|Letterboxd|Lichess|Lobsters|Medium|Minecraft|
Mix|MixCloud|Myspace|NPM|NameMC|OK|ORCID|Pastebin|Patreon|Pinterest|Poshmark|ProductHunt|PyPi|Quora|Redbubble|Reddit|
Repl.it|ResearchGate|Roblox|Scribd|Slashdot|Slides|Smule|Snapchat|SoundCloud|SourceForge|Speedrun.com|Spotify|
StackOverflow|Steam|Strava|Substack|Telegram|Tellonym.me|Threads|TikTok|Trakt|Trello|TryHackMe|Tumblr|Twitch|Twitter|
Unsplash|Upwork|VK|VSCO|Venmo|Vimeo|Wattpad|Weblate|Weebly|Wikipedia|Wix|WordPress|WordPressOrg|Xbox Gamertag|YouTube|
kofi|last.fm|mastodon.social|osu!
"""


def _names(block: str) -> list[str]:
    return [n for n in block.replace("\n", "").split("|") if n]


def focused_sites(tool: str) -> list[str] | None:
    """The focused list for a tool, or None when the full list is configured."""
    from app.config import get_settings

    if get_settings().username_sites != "focused":
        return None
    return _names(SHERLOCK_FOCUSED if tool == "sherlock" else MAIGRET_FOCUSED)
