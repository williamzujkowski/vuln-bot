module.exports = function (eleventyConfig) {
  // Copy static assets
  eleventyConfig.addPassthroughCopy("src/assets");
  eleventyConfig.addPassthroughCopy("src/api");

  // Watch for changes
  eleventyConfig.addWatchTarget("src/assets/");

  // Add date formatting filter
  eleventyConfig.addFilter("dateFormat", (date) => {
    return new Date(date).toLocaleDateString("en-US", {
      year: "numeric",
      month: "long",
      day: "numeric",
    });
  });

  // Add RFC822 date filter for RSS feeds
  eleventyConfig.addFilter("date", (date, format) => {
    const d = new Date(date);
    if (format === "%a, %d %b %Y %H:%M:%S %z") {
      // RFC822 format for RSS
      const days = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
      const months = [
        "Jan",
        "Feb",
        "Mar",
        "Apr",
        "May",
        "Jun",
        "Jul",
        "Aug",
        "Sep",
        "Oct",
        "Nov",
        "Dec",
      ];
      const day = days[d.getUTCDay()];
      const dayNum = d.getUTCDate().toString().padStart(2, "0");
      const month = months[d.getUTCMonth()];
      const year = d.getUTCFullYear();
      const hours = d.getUTCHours().toString().padStart(2, "0");
      const minutes = d.getUTCMinutes().toString().padStart(2, "0");
      const seconds = d.getUTCSeconds().toString().padStart(2, "0");
      return `${day}, ${dayNum} ${month} ${year} ${hours}:${minutes}:${seconds} +0000`;
    } else if (format === "%Y-%m-%dT%H:%M:%SZ") {
      // ISO8601 format for Atom
      return d.toISOString();
    }
    return d.toString();
  });

  // Add absolute URL filter
  eleventyConfig.addFilter("absoluteUrl", (url) => {
    return `https://williamzujkowski.github.io${url}`;
  });

  // Add round filter for numbers
  eleventyConfig.addFilter("round", (value, decimals) => {
    return Number(Math.round(value + "e" + decimals) + "e-" + decimals);
  });

  // Add limit filter
  eleventyConfig.addFilter("limit", (array, limit) => {
    return array.slice(0, limit);
  });

  // Add JSON stringify filter
  eleventyConfig.addFilter("jsonify", (obj) => {
    return JSON.stringify(obj, null, 2);
  });

  return {
    dir: {
      input: "src",
      output: "public",
      includes: "_includes",
      data: "_data",
    },
    templateFormats: ["njk", "md", "html"],
    pathPrefix: "/vuln-bot/",
    htmlTemplateEngine: "njk",
    markdownTemplateEngine: "njk",
  };
};
