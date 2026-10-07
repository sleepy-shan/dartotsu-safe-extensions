async function searchResults(keyword) {
    const results = [];
    const headers = {
        'Referer': 'https://gojo.live/',
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
    };

    const encodedKeyword = encodeURIComponent(keyword);
    const response = await fetchv2(`https://backend.gojo.live/api/anime/search?query=${encodedKeyword}&page=1`, headers);
    const json = await response.json();

    json.results.forEach(anime => {
        const title = anime.title.english || anime.title.romaji || anime.title.native || "Unknown Title";
        const image = anime.coverImage.large;
        const href = `${anime.id}`;

        if (title && href && image) {
            results.push({
                title: title,
                image: image,
                href: href
            });
        } else {
            console.error("Missing or invalid data in search result item:", {
                title,
                href,
                image
            });
        }
    });

    return JSON.stringify(results);
}

async function extractDetails(id) {
    const results = [];
    const headers = {
        'Referer': 'https://gojo.live/',
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
    };

    const response = await fetchv2(`https://backend.gojo.live/api/anime/info/${id}`, headers);
    const json = await response.json();

    const description = cleanHtmlSymbols(json.description) || "No description available"; // Handling case where description might be missing

    results.push({
        description: description.replace(/<br>/g, ''),
        aliases: 'N/A',
        airdate: 'N/A'
    });

    return JSON.stringify(results);
}

async function extractEpisodes(id) {
    const results = [];
    const headers = {
        'Referer': 'https://gojo.live/',
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
    };

    const response = await fetchv2(`https://backend.gojo.live/api/anime/episodes/${id}`, headers);
    const json = await response.json();

    const providers = ["pahe", "zaza", "strix"]
        .map(p => ({ id: p, episodes: (json.find(j => j.providerId === p)?.episodes || []) }));

    const paheEpisodes = providers.find(p => p.id === "pahe").episodes;

    for (const ep of paheEpisodes) {
        const parts = [`${id}/pahe/${ep.number}/${ep.id}`];

        for (const provider of providers) {
            if (provider.id === "pahe") continue; // already added

            const foundEp = provider.episodes.find(e => e.number === ep.number);
            if (foundEp) {
                parts.push(`${provider.id}/${foundEp.number}/${foundEp.id}`);
            }
        }

        results.push({
            href: parts.join('/'),
            number: ep.number
        });
    }

    console.error(JSON.stringify(results));
    return JSON.stringify(results);
}

async function extractStreamUrl(url) {
    const parts = url.split('/');
    const [id, ...rest] = parts;

    const providers = [];
    for (let i = 0; i < rest.length; i += 3) {
        const [provider, number, episodeId] = rest.slice(i, i + 3);
        if (provider && episodeId && episodeId !== "null") {
            providers.push({ provider, number, episodeId });
        }
    }

    console.error(`ID: ${id}, Providers: ${providers.map(p => p.provider).join(', ')}`);

    const headers = {
        'Referer': 'https://gojo.live/',
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
    };

    const fetches = providers.map(({ provider, number, episodeId }) =>
        fetchv2(
            `https://backend.gojo.live/api/anime/tiddies?provider=${provider}&id=${id}&num=${number}&subType=sub&watchId=${episodeId}&dub_id=null`,
            headers
        )
            .then(res => res.json())
            .then(json => (json.sources || []).map(src => ({ provider, quality: src.quality, url: src.url })))
            .catch(() => [])
    );

    const allSources = (await Promise.all(fetches)).flat();

    const streams = [];
    for (const { provider, quality, url: streamUrl } of allSources) {
        streams.push(`${provider} - ${quality}`, streamUrl);
    }

    const result = { streams };
    console.log(JSON.stringify(result));
    return JSON.stringify(result);
}



function cleanHtmlSymbols(string) {
    if (!string) return "";

    return string
        .replace(/&#8217;/g, "'")
        .replace(/&#8211;/g, "-")
        .replace(/&#[0-9]+;/g, "")
        .replace(/\r?\n|\r/g, " ")  
        .replace(/\s+/g, " ")       
        .replace(/<i[^>]*>(.*?)<\/i>/g, "$1")
        .replace(/<b[^>]*>(.*?)<\/b>/g, "$1") 
        .replace(/<[^>]+>/g, "")
        .trim();                 
}
