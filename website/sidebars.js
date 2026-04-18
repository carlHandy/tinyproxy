// @ts-check

/** @type {import('@docusaurus/plugin-content-docs').SidebarsConfig} */
const sidebars = {
  tutorialSidebar: [
    'intro',
    {
      type: 'category',
      label: 'Getting Started',
      items: [
        'getting-started/installation',
        'getting-started/quick-start',
        'getting-started/docker',
      ],
    },
    {
      type: 'category',
      label: 'Configuration',
      items: ['configuration/vhosts'],
    },
    {
      type: 'category',
      label: 'Features',
      items: [
        'features/automatic-tls',
        'features/bot-protection',
        'features/dashboard',
        'features/security',
      ],
    },
    'deployment',
    'development',
  ],
};

export default sidebars;
