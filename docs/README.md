# Security Tool Builder - Documentation

This directory contains the GitHub Pages site for visualizing and interacting with the AI-generated security tools.

## Features

- **Interactive Tool Browser**: Browse all security tools with filtering and search
- **Category Organization**: Tools organized by category (AI Security, Cloud, IoT, etc.)
- **Status Tracking**: Visual status indicators (Todo, In Progress, Completed, etc.)
- **Detailed View**: Modal popup with full tool details and requirements
- **GitHub Integration**: Direct links to tool branches and code
- **Real-time Data**: Loads tool data directly from the YAML backlog
- **Responsive Design**: Works on desktop and mobile devices

## Technology Stack

- **Static Site**: GitHub Pages with Jekyll
- **Frontend**: HTML5, Tailwind CSS, Alpine.js
- **Data Source**: YAML backlog parsed with js-yaml
- **Icons**: Font Awesome
- **Hosting**: GitHub Pages

## Local Development

To test the site locally:

1. Install Jekyll: `gem install jekyll bundler`
2. Serve the site: `jekyll serve`
3. Open: `http://localhost:4000/builder-agent`

## Deployment

The site automatically deploys via GitHub Actions when changes are pushed to the main branch.

## Live Site

Visit: [https://lewiswigmore.github.io/builder-agent](https://lewiswigmore.github.io/builder-agent)