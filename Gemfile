source "https://rubygems.org"

# Jekyll 4, not the `github-pages` gem.
#
# `github-pages` pins Jekyll 3.9.0, which cannot run on Ruby 3.2 or newer: it
# needs `csv` and friends that left the standard library in 3.4, and then calls
# `tainted?`, which was removed in 3.2. On Ruby 4.0 it dies before it reads a
# single page. So we build with current Jekyll and deploy with GitHub Actions
# (.github/workflows/pages.yml) instead of GitHub's own Pages builder, which
# only knows how to run the old gem.
gem "jekyll", "~> 4.4"
gem "minimal-mistakes-jekyll", "~> 4.27"
gem "webrick"

group :jekyll_plugins do
  gem "jekyll-feed"
  gem "jekyll-include-cache"
  gem "jekyll-paginate"
  gem "jekyll-sitemap"
end
