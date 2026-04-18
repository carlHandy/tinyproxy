import clsx from 'clsx';
import Heading from '@theme/Heading';
import styles from './styles.module.css';

const FeatureList = [
  {
    title: 'Security-Focused',
    description: (
      <>
        Built from the ground up with security in mind. Features modern TLS 
        standards, security headers, and safe defaults.
      </>
    ),
  },
  {
    title: 'Native Bot Detection',
    description: (
      <>
        Intersects requests at the pipeline level to block scanners, AI
        crawlers, and scrapers before they reach your backend.
      </>
    ),
  },
  {
    title: 'Built-in Dashboard',
    description: (
      <>
        Real-time observability and management through a sleek web interface
        powered by HTMX and Tailwind CSS.
      </>
    ),
  },
];

function Feature({title, description}) {
  return (
    <div className={clsx('col col--4')}>
      <div className="text--center padding-horiz--md">
        <Heading as="h3">{title}</Heading>
        <p>{description}</p>
      </div>
    </div>
  );
}

export default function HomepageFeatures() {
  return (
    <section className={styles.features}>
      <div className="container">
        <div className="row">
          {FeatureList.map((props, idx) => (
            <Feature key={idx} {...props} />
          ))}
        </div>
      </div>
    </section>
  );
}
