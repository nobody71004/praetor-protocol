export const PRAETOR_PROTOCOL = 'PRAETOR/1';
export const PRAETOR_HANDSHAKE = 'X25519 + ML-KEM-768';
export const PRAETOR_TRANSPORT = 'TCP';
export const PRAETOR_DEFAULT_PORT = 9443;
export const PRAETOR_DEFAULT_CELL_SIZE = 1024;
export const PRAETOR_CELL_OVERHEAD = 80;
export const PRAETOR_CELL_SIZES = [512, 1024, 2048, 4096];
export const PRAETOR_SERVER_KEY_BYTES = 1216;

export const PRAETOR_SUITES = [
  {
    id: 'PSEAL',
    label: 'PSEAL',
    primitive: 'SIV + commitment',
    detail: 'Default record protection',
    description: 'Nonce-misuse resistant SIV with an independent commitment.',
  },
  {
    id: 'FAST',
    label: 'FAST',
    primitive: 'PSEAL transport',
    detail: 'Routing profile',
    description: 'Routes over PSEAL on this egress; AES-256-GCM is not negotiated.',
  },
  {
    id: 'BOLT',
    label: 'BOLT',
    primitive: 'PSEAL transport',
    detail: 'Routing profile',
    description: 'Routes over PSEAL on this egress; AEGIS-128L is not negotiated.',
  },
  {
    id: 'PMARINE',
    label: 'PMARINE',
    primitive: 'PSEAL transport',
    detail: 'Experimental preset',
    description: 'Routes over PSEAL on this egress; the Rust PMARINE channel is not negotiated by the desktop client.',
  },
];

export const DEMO_ENDPOINT = '104.251.218.227:9443';
export const DEMO_SERVER_PUBLIC_KEY = '46VZiVJjOhoFKyU6DcQfBblmh9ch/5in3/B2EAwtmCLBw9dg1xsl6dMdL7J2C7UiivO4mVmSxAeaBRQVTKw3JsWaURiKPIGI6KREJCc3Q0sR2yBrimdPw8LKyjoYHwiVRDKOI9k9i4itUgEGmlezw1yeapG5ZsEjGqxei3bMXTG/ZarF/zFDn6ed4rxy4OuRc5ZwwEEPrZDANmctg8IB+gce7QuPmlEt6WJCh+KATZtq64YRLSx4iopx2+oKlkpIKmxkSdSthbWCyYoZ8eWIOxIg00hax+E4gxNMVsOs/GSvEmRJzFuceQd7tQhW9qsIM6AlpKG9dxyupCk2c3Z2/RZ2qvpOS3AWtTKKBAVQ3TA3f+QI3pNOFBAuKgQEajEEwyegb9zLbwIqJ3hCn6cM16oZ7wJw4aZPsgWsqnpR6FVvYxUdEqAplkae1soMEySPzxELqTIxtLNvJ0ktn1VbEjg5LqUJRmU5Hjpz36YlxWRJ/dubikm4vMixpEZf4yRJpZxHwfAbWrOSrMRjbGnE7gg5q2EHE7F6aoUFv8yIkni3UDMDBFgVojpbnop7LbiDvTuo5MGi4nec9LMIGJs9lSu9QiSF52wVH/qZW/BJtApsGgyA7CikGPC6FuNxFum3rNKAByMs6Ehc0bsE+tjJNVeYSoAx1TLJQVdH5OI8VoqaYgTLzjCfMdaEHUWvpdhWErg8sXSh96UIX8vOjmGkyyII5WCs5okOAgqN3gU/wjGsZqcevcCpYgJ7q7KBGlFBKrGkwSuAKSWCskEs9zgUb3eURKFqLYxDtvGYtXQSSCzGQeBduShHOteTf6w9m7YHlJJsDNdGCnMXdoutD3Ccn9aaaKiDO5sf75kn6LlNjHBimmS0NqhedhOmIwN3gvWCh0uJFFgLOyQtSEVC0FGwdvOU/5IeY1m72LQ1K9AgGXagJYDJ4VFjlQeou8nFoTLE67mgzQqvgQx+g6fMzLZn23CvlZN5TRdPYkS/70jM0Yw6YvB3tlcn+oOKL3fG7HZvV+rNtTl9JGca+ai2xqK58PmUcECpEPVwLqVgxXGTKUK2iJwLR6a8B5Yii+KiaBVochqpYCkywBZHL/tjfkZAppG9VYNcjtNw6oACwbYoPPZFWURTYAaCkigd4+BHq8K+RIUhtiUH6vSsaGR4jsIGukk9kCDP2ROoHAaBPvYalNqVu8uBPVM6vBiPsgRCYBsRvgES79JyWrtFJDad21OvyFvINJAT5wK73fpmPkyfRiOrO9cw9soeU2UGBpGHpiNQ3NgxOSNgIogUTInDEwqkzGRTd6O1YwsZUzl/kXqsxLBcWUZ4SIoBtPVcRuhMxeIQelkLqRW8tBXPw3QQ7lKvE/pXJpgZG9JRW5NFyTQMYsEK9GOaahoDfkN279CR1binU5pfMZhtxgZGjxDCDesMGcao7kV6B/iTUcJcRBZmkBpoTZeUxYhenSdmBtFXWfaFM2S41zt8yohKQgGGXMFsbAQ4ntmmWnabu/l05Le/UuEXnQVxJkSlFUddP+kz8Qym2KucywV4d9vn3sAJ1w0KYpGOLiwV5ghXIYUVGNW3pOShU/oLqDmUz+eRRuXZRzthg9qr83vp9oQ0Kz2z0DFkCw==';

export function suiteMeta(value) {
  return PRAETOR_SUITES.find((suite) => suite.id === value) || PRAETOR_SUITES[0];
}

export function base64ByteLength(value) {
  try {
    return atob(String(value || '').replace(/\s+/g, '')).length;
  } catch {
    return 0;
  }
}

export function cellWireSize(cellSize) {
  return Number(cellSize || PRAETOR_DEFAULT_CELL_SIZE) + PRAETOR_CELL_OVERHEAD;
}

export function endpointPort(endpoint) {
  const match = String(endpoint || '').match(/:(\d{1,5})$/);
  return match ? match[1] : String(PRAETOR_DEFAULT_PORT);
}
