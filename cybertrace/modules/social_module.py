"""Social media OSINT module.

Searches public social media APIs and platforms for profile, post,
and activity intelligence.

Sources (no key required):
- Reddit  — user profile + search (public JSON API)
- Bluesky — profile + post search (public AT Protocol API)
- Mastodon (mastodon.social) — account + post search (public API)
- GitHub  — user profile + public repos (unauthenticated, rate-limited)

Sources (API key required):
- GitHub  — user profile + repos, higher rate limit (github token)
- Telegram — public channel/group info (telegram_bot token)

LIMITATIONS:
- Twitter/X: no free public API since 2023. Omitted.
- Instagram/Facebook: require authenticated sessions. Omitted.
- LinkedIn: aggressive anti-scraping. Omitted.
- TikTok: no stable public OSINT API. Omitted.
"""

import asyncio
from datetime import datetime
from typing import Any, Dict, List, Optional
from urllib.parse import quote_plus

from .base import BaseModule, ModuleResult, SourceResult


class SocialModule(BaseModule):
    """
    Social media footprint analysis across Reddit, Bluesky, Mastodon,
    GitHub, and optionally Telegram.

    SUCCESS RATE: 80% — free public APIs cover the major open platforms.
    Results for private/deleted accounts will be sparse.

    Supported target types:
    - username  — profile lookup + posts
    - email     — search-based (no direct profile lookup on most platforms)
    - name      — search-based
    - domain    — search for mentions/repos
    """

    name = "social"
    description = "Social media footprint: Reddit, Bluesky, Mastodon, GitHub, Telegram"
    supported_types = {'username', 'email', 'name', 'domain'}

    async def search(self, target: str, **options) -> ModuleResult:
        """
        Search social platforms for the given target.

        Args:
            target: Username, email, real name, or domain string.
            **options: Accepts 'target_type' override.

        Returns:
            ModuleResult with per-platform findings and aggregate summary.
        """
        target_type = options.get('target_type', 'username')
        query = target.strip()

        result = ModuleResult(
            target=query,
            target_type=target_type,
            module=self.name,
        )

        sources = [
            ('reddit', self._search_reddit(query)),
            ('bluesky', self._search_bluesky(query)),
            ('mastodon', self._search_mastodon(query)),
            ('github', self._search_github(query)),
        ]

        if self.config.api_keys.has('telegram_bot'):
            sources.append(('telegram', self._search_telegram(query)))

        await self.run_sources(sources, result)

        result.summary = self._build_summary(result)
        result.end_time = datetime.utcnow()
        return result

    # ------------------------------------------------------------------ #
    # Reddit                                                               #
    # ------------------------------------------------------------------ #

    async def _search_reddit(self, query: str) -> SourceResult:
        """
        Reddit public JSON API.

        - User profile: reddit.com/user/{query}/about.json
        - Site-wide search: reddit.com/search.json?q={query}

        No auth required. Reddit allows unauthenticated JSON reads.
        Rate limit: ~60 req/min for OAuth, lower without.
        """
        headers = {
            'User-Agent': 'CyberTrace OSINT/1.0 (research tool)',
        }

        profile_data: Optional[Dict[str, Any]] = None
        profile_exists = False

        # ── User profile ──────────────────────────────────────────────────
        profile_url = f"https://www.reddit.com/user/{query}/about.json"
        raw_profile = await self.fetch_json(profile_url, headers=headers, retries=1)

        if raw_profile and raw_profile.get('kind') == 't2':
            d = raw_profile.get('data', {})
            profile_exists = True
            profile_data = {
                'username': d.get('name'),
                'id': d.get('id'),
                'created_utc': d.get('created_utc'),
                'comment_karma': d.get('comment_karma', 0),
                'link_karma': d.get('link_karma', 0),
                'total_karma': d.get('total_karma') or (
                    d.get('comment_karma', 0) + d.get('link_karma', 0)
                ),
                'is_gold': d.get('is_gold', False),
                'is_mod': d.get('is_mod', False),
                'verified': d.get('verified', False),
                'has_verified_email': d.get('has_verified_email', False),
                'profile_url': f"https://www.reddit.com/user/{query}",
                'icon_img': d.get('icon_img') or None,
                'subreddit': {
                    'display_name': (d.get('subreddit') or {}).get('display_name_prefixed'),
                    'subscribers': (d.get('subreddit') or {}).get('subscribers'),
                    'public_description': (d.get('subreddit') or {}).get('public_description') or None,
                },
            }

        # ── Site-wide search ──────────────────────────────────────────────
        search_url = (
            f"https://www.reddit.com/search.json"
            f"?q={quote_plus(query)}&limit=10&type=all&sort=relevance"
        )
        raw_search = await self.fetch_json(search_url, headers=headers, retries=1)

        search_posts: List[Dict[str, Any]] = []
        if raw_search:
            items = (raw_search.get('data') or {}).get('children', [])
            for item in items[:10]:
                d = item.get('data', {})
                search_posts.append({
                    'title': d.get('title') or d.get('body', '')[:100],
                    'subreddit': d.get('subreddit_name_prefixed') or d.get('subreddit'),
                    'author': d.get('author'),
                    'score': d.get('score'),
                    'url': f"https://www.reddit.com{d.get('permalink', '')}" if d.get('permalink') else None,
                    'created_utc': d.get('created_utc'),
                    'type': item.get('kind'),  # 't1'=comment, 't3'=link/post
                })

        data: Dict[str, Any] = {
            'profile_found': profile_exists,
            'search_post_count': len(search_posts),
            'search_posts': search_posts,
        }
        if profile_data:
            data['profile'] = profile_data

        return SourceResult(
            source='reddit',
            success=True,
            data=data,
        )

    # ------------------------------------------------------------------ #
    # Bluesky (AT Protocol)                                                #
    # ------------------------------------------------------------------ #

    async def _search_bluesky(self, query: str) -> SourceResult:
        """
        Bluesky public AT Protocol API — no authentication required.

        - Profile: public.api.bsky.app/xrpc/app.bsky.actor.getProfile?actor={handle}
        - Posts:   public.api.bsky.app/xrpc/app.bsky.feed.searchPosts?q={query}

        Note: Profile lookup works best with a Bluesky handle (user.bsky.social).
        Search works on any query string.
        """
        headers = {'User-Agent': 'CyberTrace OSINT/1.0'}

        # ── Profile ───────────────────────────────────────────────────────
        profile_url = (
            f"https://public.api.bsky.app/xrpc/app.bsky.actor.getProfile"
            f"?actor={quote_plus(query)}"
        )
        profile_raw = await self.fetch_json(profile_url, headers=headers, retries=1)

        profile_data: Optional[Dict[str, Any]] = None
        if profile_raw and profile_raw.get('did'):
            profile_data = {
                'did': profile_raw.get('did'),
                'handle': profile_raw.get('handle'),
                'display_name': profile_raw.get('displayName') or None,
                'description': profile_raw.get('description') or None,
                'followers_count': profile_raw.get('followersCount', 0),
                'follows_count': profile_raw.get('followsCount', 0),
                'posts_count': profile_raw.get('postsCount', 0),
                'created_at': profile_raw.get('createdAt') or None,
                'avatar': profile_raw.get('avatar') or None,
                'profile_url': f"https://bsky.app/profile/{profile_raw.get('handle', query)}",
                'indexed_at': profile_raw.get('indexedAt') or None,
            }

        # ── Post search ───────────────────────────────────────────────────
        posts_url = (
            f"https://public.api.bsky.app/xrpc/app.bsky.feed.searchPosts"
            f"?q={quote_plus(query)}&limit=10"
        )
        posts_raw = await self.fetch_json(posts_url, headers=headers, retries=1)

        search_posts: List[Dict[str, Any]] = []
        if posts_raw and isinstance(posts_raw.get('posts'), list):
            for post in posts_raw['posts'][:10]:
                record = post.get('record', {})
                author = post.get('author', {})
                search_posts.append({
                    'text': record.get('text', '')[:300],
                    'author_handle': author.get('handle'),
                    'author_display_name': author.get('displayName') or None,
                    'created_at': record.get('createdAt'),
                    'like_count': post.get('likeCount', 0),
                    'repost_count': post.get('repostCount', 0),
                    'uri': post.get('uri'),
                })

        data: Dict[str, Any] = {
            'profile_found': profile_data is not None,
            'search_post_count': len(search_posts),
            'search_posts': search_posts,
        }
        if profile_data:
            data['profile'] = profile_data

        return SourceResult(
            source='bluesky',
            success=True,
            data=data,
        )

    # ------------------------------------------------------------------ #
    # Mastodon                                                             #
    # ------------------------------------------------------------------ #

    async def _search_mastodon(self, query: str) -> SourceResult:
        """
        Mastodon.social public search API — no authentication required.

        API: mastodon.social/api/v2/search?q={query}&resolve=false&limit=10

        Returns accounts, statuses (posts), and hashtags matching the query.
        Note: resolve=false means we don't attempt WebFinger resolution of
        remote accounts (avoids extra latency + permissions).
        """
        url = (
            f"https://mastodon.social/api/v2/search"
            f"?q={quote_plus(query)}&resolve=false&limit=10"
        )
        headers = {
            'User-Agent': 'CyberTrace OSINT/1.0',
            'Accept': 'application/json',
        }

        data = await self.fetch_json(url, headers=headers, retries=1)

        if not data:
            return SourceResult(
                source='mastodon',
                success=False,
                error='No response from Mastodon',
            )

        # ── Accounts ─────────────────────────────────────────────────────
        accounts: List[Dict[str, Any]] = []
        for acct in (data.get('accounts') or [])[:10]:
            accounts.append({
                'id': acct.get('id'),
                'username': acct.get('username'),
                'acct': acct.get('acct'),
                'display_name': acct.get('display_name') or None,
                'note': (acct.get('note') or '')[:200],  # HTML bio
                'followers_count': acct.get('followers_count', 0),
                'following_count': acct.get('following_count', 0),
                'statuses_count': acct.get('statuses_count', 0),
                'created_at': acct.get('created_at'),
                'url': acct.get('url'),
                'avatar': acct.get('avatar') or None,
                'bot': acct.get('bot', False),
            })

        # ── Statuses (posts) ──────────────────────────────────────────────
        statuses: List[Dict[str, Any]] = []
        for status in (data.get('statuses') or [])[:10]:
            account = status.get('account', {})
            statuses.append({
                'id': status.get('id'),
                'content': (status.get('content') or '')[:300],  # HTML
                'created_at': status.get('created_at'),
                'favourites_count': status.get('favourites_count', 0),
                'reblogs_count': status.get('reblogs_count', 0),
                'url': status.get('url'),
                'author': account.get('acct'),
            })

        # ── Hashtags ──────────────────────────────────────────────────────
        hashtags = [
            {'name': ht.get('name'), 'url': ht.get('url')}
            for ht in (data.get('hashtags') or [])[:5]
        ]

        return SourceResult(
            source='mastodon',
            success=True,
            data={
                'account_count': len(accounts),
                'accounts': accounts,
                'status_count': len(statuses),
                'statuses': statuses,
                'hashtag_count': len(hashtags),
                'hashtags': hashtags,
            },
        )

    # ------------------------------------------------------------------ #
    # GitHub                                                               #
    # ------------------------------------------------------------------ #

    async def _search_github(self, query: str) -> SourceResult:
        """
        GitHub public API — user profile and recent public repos.

        Unauthenticated: 60 req/hour. Authenticated (github token): 5000 req/hour.
        We send the token header when available.
        """
        headers: Dict[str, str] = {
            'Accept': 'application/vnd.github.v3+json',
            'User-Agent': 'CyberTrace OSINT/1.0',
        }

        if self.config.api_keys.has('github'):
            headers['Authorization'] = f"token {self.config.api_keys.get('github')}"

        # ── User profile ──────────────────────────────────────────────────
        user_url = f"https://api.github.com/users/{query}"
        user_raw = await self.fetch_json(user_url, headers=headers, retries=1)

        if not user_raw or user_raw.get('message') == 'Not Found':
            # User not found — still try search
            profile_data = None
        else:
            profile_data = {
                'login': user_raw.get('login'),
                'id': user_raw.get('id'),
                'name': user_raw.get('name') or None,
                'company': user_raw.get('company') or None,
                'blog': user_raw.get('blog') or None,
                'location': user_raw.get('location') or None,
                'email': user_raw.get('email') or None,
                'bio': user_raw.get('bio') or None,
                'twitter_username': user_raw.get('twitter_username') or None,
                'public_repos': user_raw.get('public_repos', 0),
                'public_gists': user_raw.get('public_gists', 0),
                'followers': user_raw.get('followers', 0),
                'following': user_raw.get('following', 0),
                'created_at': user_raw.get('created_at'),
                'updated_at': user_raw.get('updated_at'),
                'html_url': user_raw.get('html_url'),
                'avatar_url': user_raw.get('avatar_url') or None,
                'type': user_raw.get('type'),  # 'User' or 'Organization'
                'site_admin': user_raw.get('site_admin', False),
            }

        # ── Public repos ──────────────────────────────────────────────────
        repos: List[Dict[str, Any]] = []
        if profile_data:
            repos_url = (
                f"https://api.github.com/users/{query}/repos"
                f"?per_page=10&sort=updated&type=public"
            )
            repos_raw = await self.fetch_json(repos_url, headers=headers, retries=1)

            if repos_raw and isinstance(repos_raw, list):
                for repo in repos_raw[:10]:
                    repos.append({
                        'name': repo.get('name'),
                        'full_name': repo.get('full_name'),
                        'description': repo.get('description') or None,
                        'language': repo.get('language') or None,
                        'stars': repo.get('stargazers_count', 0),
                        'forks': repo.get('forks_count', 0),
                        'updated_at': repo.get('updated_at'),
                        'html_url': repo.get('html_url'),
                        'topics': repo.get('topics', []),
                        'is_fork': repo.get('fork', False),
                    })

        data: Dict[str, Any] = {
            'profile_found': profile_data is not None,
            'repo_count': len(repos),
            'repos': repos,
        }
        if profile_data:
            data['profile'] = profile_data

        return SourceResult(
            source='github',
            success=True,
            data=data,
        )

    # ------------------------------------------------------------------ #
    # Telegram                                                             #
    # ------------------------------------------------------------------ #

    async def _search_telegram(self, query: str) -> SourceResult:
        """
        Telegram Bot API — public channel/group lookup.

        Uses getChat to fetch metadata for a public channel or group when
        the query looks like a Telegram username (@handle).

        Requires a Telegram bot token (telegram_bot key).
        Only works for PUBLIC channels/groups — private chats return 400.

        Note: The Telegram Bot API cannot search for users by username;
        it can only resolve channels/groups the bot can see.
        """
        token = self.config.api_keys.get('telegram_bot')
        if not token:
            return SourceResult(
                source='telegram',
                success=False,
                error='No Telegram bot token',
            )

        # Normalise: strip leading @ if present
        chat_id = query.lstrip('@')
        url = f"https://api.telegram.org/bot{token}/getChat?chat_id=@{chat_id}"

        data = await self.fetch_json(url, retries=1)

        if not data:
            return SourceResult(
                source='telegram',
                success=False,
                error='No response from Telegram API',
            )

        if not data.get('ok'):
            error_desc = data.get('description', 'Unknown error')
            if 'chat not found' in error_desc.lower() or '400' in str(data.get('error_code', '')):
                return SourceResult(
                    source='telegram',
                    success=True,
                    data={'found': False, 'note': 'Channel/group not found or is private'},
                )
            return SourceResult(
                source='telegram',
                success=False,
                error=error_desc,
            )

        chat = data.get('result', {})
        chat_type = chat.get('type', '')  # 'channel', 'supergroup', 'group', 'private'

        parsed: Dict[str, Any] = {
            'found': True,
            'chat_id': chat.get('id'),
            'type': chat_type,
            'title': chat.get('title') or chat.get('username') or None,
            'username': chat.get('username') or None,
            'description': chat.get('description') or None,
            'invite_link': chat.get('invite_link') or None,
            'member_count': chat.get('member_count') or chat.get('members_count') or None,
            'is_verified': chat.get('is_verified', False),
            'is_scam': chat.get('is_scam', False),
            'is_fake': chat.get('is_fake', False),
            'has_protected_content': chat.get('has_protected_content', False),
            'profile_url': (
                f"https://t.me/{chat.get('username')}"
                if chat.get('username') else None
            ),
        }

        # Photo
        photo = chat.get('photo')
        if photo:
            parsed['has_photo'] = True
            parsed['photo_file_id'] = photo.get('big_file_id') or photo.get('small_file_id')

        return SourceResult(source='telegram', success=True, data=parsed)

    # ------------------------------------------------------------------ #
    # Summary                                                              #
    # ------------------------------------------------------------------ #

    def _build_summary(self, result: ModuleResult) -> Dict[str, Any]:
        summary: Dict[str, Any] = {
            'target': result.target,
            'platforms_found': [],
            'platforms_searched': [],
            'total_posts_found': 0,
            'notable_findings': [],
        }

        # ── Reddit ────────────────────────────────────────────────────────
        reddit = result.sources.get('reddit')
        if reddit and reddit.success:
            summary['platforms_searched'].append('reddit')
            if reddit.data.get('profile_found'):
                summary['platforms_found'].append('reddit')
                profile = reddit.data.get('profile', {})
                summary['reddit'] = {
                    'username': profile.get('username'),
                    'karma': profile.get('total_karma', 0),
                    'profile_url': profile.get('profile_url'),
                }
                if profile.get('username'):
                    result.related.append(profile['username'])
            summary['total_posts_found'] += reddit.data.get('search_post_count', 0)

        # ── Bluesky ───────────────────────────────────────────────────────
        bsky = result.sources.get('bluesky')
        if bsky and bsky.success:
            summary['platforms_searched'].append('bluesky')
            if bsky.data.get('profile_found'):
                summary['platforms_found'].append('bluesky')
                profile = bsky.data.get('profile', {})
                summary['bluesky'] = {
                    'handle': profile.get('handle'),
                    'display_name': profile.get('display_name'),
                    'followers': profile.get('followers_count', 0),
                    'posts_count': profile.get('posts_count', 0),
                    'profile_url': profile.get('profile_url'),
                }
            summary['total_posts_found'] += bsky.data.get('search_post_count', 0)

        # ── Mastodon ──────────────────────────────────────────────────────
        masto = result.sources.get('mastodon')
        if masto and masto.success:
            summary['platforms_searched'].append('mastodon')
            acct_count = masto.data.get('account_count', 0)
            if acct_count > 0:
                summary['platforms_found'].append('mastodon')
                top_acct = masto.data.get('accounts', [{}])[0]
                summary['mastodon'] = {
                    'account_count': acct_count,
                    'top_account': top_acct.get('acct'),
                    'followers': top_acct.get('followers_count', 0),
                }
            summary['total_posts_found'] += masto.data.get('status_count', 0)

        # ── GitHub ────────────────────────────────────────────────────────
        gh = result.sources.get('github')
        if gh and gh.success:
            summary['platforms_searched'].append('github')
            if gh.data.get('profile_found'):
                summary['platforms_found'].append('github')
                profile = gh.data.get('profile', {})
                summary['github'] = {
                    'login': profile.get('login'),
                    'name': profile.get('name'),
                    'public_repos': profile.get('public_repos', 0),
                    'followers': profile.get('followers', 0),
                    'location': profile.get('location'),
                    'email': profile.get('email'),
                    'html_url': profile.get('html_url'),
                }
                # Surface email and Twitter for cross-correlation
                if profile.get('email'):
                    result.related.append(profile['email'])
                if profile.get('twitter_username'):
                    result.related.append(profile['twitter_username'])
                    summary['notable_findings'].append(
                        f"GitHub links to Twitter: @{profile['twitter_username']}"
                    )
                # Surface top repos
                summary['github']['top_repos'] = [
                    r.get('full_name') for r in gh.data.get('repos', [])[:5]
                ]

        # ── Telegram ──────────────────────────────────────────────────────
        tg = result.sources.get('telegram')
        if tg and tg.success:
            summary['platforms_searched'].append('telegram')
            if tg.data.get('found'):
                summary['platforms_found'].append('telegram')
                summary['telegram'] = {
                    'title': tg.data.get('title'),
                    'username': tg.data.get('username'),
                    'type': tg.data.get('type'),
                    'members': tg.data.get('member_count'),
                    'is_scam': tg.data.get('is_scam', False),
                    'profile_url': tg.data.get('profile_url'),
                }
                if tg.data.get('is_scam'):
                    summary['notable_findings'].append('Telegram marks this account as a SCAM')

        # ── Derived ───────────────────────────────────────────────────────
        summary['platform_hit_count'] = len(summary['platforms_found'])

        return summary
