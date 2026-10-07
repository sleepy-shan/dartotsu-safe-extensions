function searchResults(html) {
    const results = [];
    const baseUrl = "https://animefenix2.tv/";

    const filmListRegex = /<li>[\s\S]*?<a href="([^"]+)">[\s\S]*?<img[^>]*src="([^"]+)"[^>]*>[\s\S]*?<p>([^<]+)<\/p>/g;
    let match;

    while ((match = filmListRegex.exec(html)) !== null) {
        const href = match[1] ? match[1].trim() : '';
        const imageUrl = match[2] ? match[2].trim() : '';
        const title = match[3] ? match[3].trim() : '';

        if (title && href) {
            results.push({
                title,
                image: imageUrl,
                href: href.startsWith("/") ? baseUrl + href.slice(1) : baseUrl + href
            });
        }
    }
    console.log(results);
    return results;
}

function extractDetails(html) {
    const details = [];
 
    const descriptionMatch = html.match(/<p class="text-gray-300">([\s\S]*?)<\/p>/);
    let description = descriptionMatch ? descriptionMatch[1].trim() : '';
 
    const airdateMatch = html.match(/<span class="font-semibold text-gray-400">Año:<\/span>\s*(\d{4})/);
    let airdate = airdateMatch ? airdateMatch[1].trim() : '';
 
    if (description || airdate) {
        details.push({
            description: description || 'N/A',
            aliases: 'N/A',
            airdate: airdate || 'N/A'
        });
    }
    console.log(details);
    return details;
}

function extractEpisodes(html) {
    const episodes = [];
    const baseUrl = "https://animefenix2.tv/";
 
    const episodeMatches = [...html.matchAll(/<a href="([^"]+)".*?>[\s\S]*?<span class="font-semibold">\s*Episodio (\d+)\s*<\/span>/g)];
 
    episodeMatches.forEach(match => {
        let href = match[1];
        const number = match[2];
 
        if (!href.startsWith("https")) {
            href = baseUrl + (href.startsWith("/") ? href.slice(1) : href);
        }
 
        episodes.push({
            href: href,
            number: number
        });
    });
    console.log(episodes.reverse());
    return episodes.reverse();
}
 
async function extractStreamUrl(html) {
    try {
        const sourceMatch = html.match(/https:\/\/re\.ironhentai\.com\/vt\.php\?id=[^'"]+/);
        const realUrl = sourceMatch ? sourceMatch[0] : null;
        if (!realUrl) return null;

        const embedhtml = await fetch(realUrl);
        const html = await embedhtml;
        const m3u8Match = html.match(/https:\/\/str\d+\.vtube\.network\/hls\/[^'"]+\.m3u8/);

        if (m3u8Match) {
            console.log(m3u8Match[0]);
            return m3u8Match[0];
        } else {
            return null;
        }
    } catch (error) {
        return null;
    }
}
    
