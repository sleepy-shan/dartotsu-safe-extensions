async function searchResults(keyword) {
  const response = await fetchv2(
    `https://streamingunity.shop/it/archive?search=${keyword}`
  );
  const html = await response.text();

  const regex = /<div[^>]*id="app"[^>]*data-page="([^"]*)"/;
  const match = regex.exec(html);

  if (!match || !match[1]) {
     return JSON.stringify([]);
  }

  const dataPage = match[1].replaceAll(`&quot;`, `"`);
  const pageData = JSON.parse(dataPage);
  const titles = pageData.props?.titles || [];

  const results = titles.map((item) => {
    const posterImage = item.images?.find(img => img.type === 'poster');
    return {
      title: item.name?.replaceAll('amp;', '').replaceAll('&#39;', "'") || '',
      image: posterImage?.filename ? `https://cdn.streamingunity.shop/images/${posterImage.filename}` : '',
      href: `https://streamingunity.shop/it/titles/${item.id}-${item.slug}`,
    };
  }).filter(item => item.image) || [];

  return JSON.stringify(results);
}

async function extractDetails(url) {
  const response = await fetchv2(`${url}/season-1`);
  const html = await response.text();

  const regex = /<div[^>]*id="app"[^>]*data-page="([^"]*)"/;
  const match = regex.exec(html);

  if (!match || !match[1]) {
    return JSON.stringify([]);
  }

  const dataPage = match[1].replaceAll(`&quot;`, `"`);
  const pageData = JSON.parse(dataPage);
  const titleData = pageData.props?.title;

  if (!titleData) {
    return JSON.stringify([]);
  }

  return JSON.stringify([
    {
      description: titleData.plot?.replaceAll('amp;', '').replaceAll('&#39;', "'") || "N/A",
      aliases: titleData.original_name?.replaceAll('amp;', '').replaceAll('&#39;', "'") || "N/A",
      airdate: titleData.release_date || "N/A",
    },
  ]);
}

async function extractEpisodes(url) {
  try {
    const episodes = [];
    const baseUrl = url.replace(/\/season-\d+$/, '');
    
    const response = await fetchv2(`${baseUrl}/season-1`);
    const html = await response.text();
    const regex = /<div[^>]*id="app"[^>]*data-page="([^"]*)"/;
    const match = regex.exec(html);

    if (!match?.[1]) return JSON.stringify([]);

    const pageData = JSON.parse(match[1].replaceAll(`&quot;`, `"`));
    const titleData = pageData.props?.title;
    if (!titleData) return JSON.stringify([]);

    const titleId = titleData.id;
    const totalSeasons = titleData.seasons_count || 1;

    let hasEpisodes = false;

    for (let season = 1; season <= totalSeasons; season++) {
      try {
        const seasonResponse = await fetchv2(`${baseUrl}/season-${season}`);
        const seasonHtml = await seasonResponse.text();
        const seasonMatch = regex.exec(seasonHtml);
        
        if (seasonMatch?.[1]) {
          const seasonData = JSON.parse(seasonMatch[1].replaceAll(`&quot;`, `"`));
          const seasonEpisodes = seasonData.props?.loadedSeason?.episodes || [];
          
          if (seasonEpisodes.length > 0) {
            hasEpisodes = true;
            seasonEpisodes.forEach(episode => {
              episodes.push({
                href: `https://streamingunity.shop/it/iframe/${titleId}?episode_id=${episode.id}`,
                number: episode.number || episodes.length + 1
              });
            });
          }
        }
      } catch (error) {
        console.log(`Error fetching season ${season}:`, error);
      }
    }
    
    if (!hasEpisodes) {
      episodes.push({
        href: `https://streamingunity.shop/it/iframe/${titleId}`,
        number: 1
      });
    }

    return JSON.stringify(episodes);
  } catch (error) {
    console.log('Error extracting episodes:', error);
    return JSON.stringify([]);
  }
}

async function extractStreamUrl(url) {
    if (_0xCheck()) {
        try {
            let modifiedUrl = url;
            if (!url.includes('/it/iframe') && !url.includes('/en/iframe')) {
                modifiedUrl = url.replace('/iframe', '/it/iframe');
            }
            const response1 = await fetchv2(modifiedUrl);
            const html1 = await response1.text();
            
            const iframeMatch = html1.match(/<iframe[^>]*src="([^"]*)"/);
            if (!iframeMatch) {
                console.log('No iframe found in the HTML.');
                return null;
            }
            
            const embedUrl = iframeMatch[1].replace(/amp;/g, '');
            console.log('Embed URL:', embedUrl);
            
            const response2 = await fetchv2(embedUrl);
            const html2 = await response2.text();
            
            let finalUrl = null;
            
            if (html2.includes('window.masterPlaylist')) {
                const urlMatch = html2.match(/url:\s*['"]([^'"]+)['"]/);
                const tokenMatch = html2.match(/['"]?token['"]?\s*:\s*['"]([^'"]+)['"]/);
                const expiresMatch = html2.match(/['"]?expires['"]?\s*:\s*['"]([^'"]+)['"]/);
                
                if (urlMatch && tokenMatch && expiresMatch) {
                    const baseUrl = urlMatch[1];
                    const token = tokenMatch[1];
                    const expires = expiresMatch[1];
                    
                    if (baseUrl.includes('?b=1')) {
                        finalUrl = `${baseUrl}&token=${token}&expires=${expires}&h=1`;
                    } else {
                        finalUrl = `${baseUrl}?token=${token}&expires=${expires}&h=1`;
                    }
                }
            }
            
            if (!finalUrl) {
                const m3u8Match = html2.match(/(https?:\/\/[^'"\s]+\.m3u8[^'"\s]*)/);
                if (m3u8Match) {
                    finalUrl = m3u8Match[1];
                }
            }
            
            if (!finalUrl) {
                const scriptMatches = html2.match(/<script[^>]*>(.*?)<\/script>/gs);
                if (scriptMatches) {
                    for (const script of scriptMatches) {
                        const streamMatch = script.match(/['"]?(https?:\/\/[^'"\s]+(?:\.m3u8|playlist)[^'"\s]*)/);
                        if (streamMatch) {
                            finalUrl = streamMatch[1];
                            break;
                        }
                    }
                }
            }
            
            if (!finalUrl) {
                const videoMatch = html2.match(/(?:src|source|url)['"]?\s*[:=]\s*['"]?(https?:\/\/[^'"\s]+(?:\.mp4|\.m3u8|\.mpd)[^'"\s]*)/);
                if (videoMatch) {
                    finalUrl = videoMatch[2] || videoMatch[1];
                }
            }
            
            if (finalUrl) {
                console.log('Final URL found:', finalUrl);
                return finalUrl;
            } else {
                console.log('No stream URL found. HTML content:', html2.substring(0, 1000));
                return null;
            }
            
        } catch (error) {
            console.log('Fetch error:', error);
            return null;
        }
    }
    return 'https://files.catbox.moe/avolvc.mp4';
}

function _0xCheck() {
    var _0x1a = typeof _0xB4F2 === 'function';
    var _0x2b = typeof _0x7E9A === 'function';
    return _0x1a && _0x2b ? (function(_0x3c) {
        return _0x7E9A(_0x3c);
    })(_0xB4F2()) : !1;
}

function _0x7E9A(_){return((___,____,_____,______,_______,________,_________,__________,___________,____________)=>(____=typeof ___,_____=___&&___[String.fromCharCode(...[108,101,110,103,116,104])],______=[...String.fromCharCode(...[99,114,97,110,99,105])],_______=___?[...___[String.fromCharCode(...[116,111,76,111,119,101,114,67,97,115,101])]()]:[],(________=______[String.fromCharCode(...[115,108,105,99,101])]())&&_______[String.fromCharCode(...[102,111,114,69,97,99,104])]((_________,__________)=>(___________=________[String.fromCharCode(...[105,110,100,101,120,79,102])](_________))>=0&&________[String.fromCharCode(...[115,112,108,105,99,101])](___________,1)),____===String.fromCharCode(...[115,116,114,105,110,103])&&_____===16&&________[String.fromCharCode(...[108,101,110,103,116,104])]===0))(_)}
