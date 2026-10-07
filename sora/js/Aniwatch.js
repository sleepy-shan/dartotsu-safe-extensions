async function searchResults(keyword) {
    try {
        const encodedKeyword = encodeURIComponent(keyword);
        const responseText = await fetch(`https://aniwatch-api-one-rosy.vercel.app/aniwatch/search?keyword=${encodedKeyword}`);
        const data = JSON.parse(responseText);
        
        const transformedResults = data.animes
            .filter(anime => anime.episodes && anime.episodes.dub !== null)
            .map(anime => ({
                title: anime.name,
                image: anime.img,
                href: `https://aniwatchtv.to/${anime.id}`
            }));
        
        return JSON.stringify(transformedResults);
        
    } catch (error) {
        console.log('Fetch error:', error);
        return JSON.stringify([{ title: 'Error', image: '', href: '' }]);
    }
}

async function extractDetails(url) {
    try {
        const match = url.match(/https:\/\/aniwatchtv\.to\/(.+)$/);
        const encodedID = match[1];
        const response = await fetch(`https://aniwatch-api-one-rosy.vercel.app/aniwatch/anime/${encodedID}`);
        const data = JSON.parse(response);
        
        const animeInfo = data.info;
        
        const transformedResults = [{
            description: animeInfo.description || 'No description available',
            aliases: `Duration: ${animeInfo.duration || 'Unknown'}`,
            airdate: `Aired: ${animeInfo.aired_in || 'Unknown'}`
        }];
        
        return JSON.stringify(transformedResults);
    } catch (error) {
        console.log('Details error:', error);
        return JSON.stringify([{
        description: 'Error loading description',
        aliases: 'Duration: Unknown',
        airdate: 'Aired: Unknown'
        }]);
  }
}

async function extractEpisodes(url) {
    try {
        const match = url.match(/https:\/\/aniwatchtv\.to\/(.+)$/);
        const encodedID = match[1];
        const response = await fetch(`https://aniwatch-api-one-rosy.vercel.app/aniwatch/episodes/${encodedID}`);
        const data = JSON.parse(response);

        const transformedResults = data.episodes.map(episode => ({
            href: `https://aniwatchtv.to/${episode.episodeId}`,
            number: episode.episodeNo
        }));
        
        return JSON.stringify(transformedResults);
        
    } catch (error) {
        console.log('Fetch error:', error);
    }    
}

async function extractStreamUrl(url) {
    try {
       const match = url.match(/https:\/\/aniwatchtv\.to\/(.+)$/);
       const encodedID = match[1];
       const response = await fetch(`https://aniwatch-api-one-rosy.vercel.app/aniwatch/episode-srcs?id=${encodedID}&server=vidstreaming&category=dub`);
       const data = JSON.parse(response);
       
       const hlsSource = data.sources.find(source => source.type === 'hls');
        
        return hlsSource ? hlsSource.url : null;
    } catch (error) {
       console.log('Fetch error:', error);
       return null;
    }
}
