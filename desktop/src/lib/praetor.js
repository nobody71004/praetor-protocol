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
export const DEMO_SERVER_PUBLIC_KEY = 'FdloELM5qLRaGDMsVemaA7g1Miwjejq7mpMsVYxRbzlFfxo6MqmQRHtv36gD8UXB5vZSV0R3xfhgq2mopPZn4CKZ5cQqCvZlulG0MrputQmlo/G31CYwDZui1oSXViUrhOaLpugyUVOUKkuTyuRMdlAGbqAWnVshjeQguzsk3Ve2eWJE+oJ/UmwVzua4J2DLouvPnsW7bicgevvFt5gvMUmxTYIR8RqOADowKXI3EGENdkY3IavPnzZfuerFQsLMUCM++nkl6OBOIOiGIiKUUmQwtIJfftuG7Og1blsoeoKhpnRzvRKi3weh8MFuxhVGEZqRA9VdiquoAQZKlAgqNDwVoRyCJly30HqsfecztvlrfGJDAkcIV3IecPuuyaUGQYyKEeoiR+xMohSOzVBOcBRvAhnIqmxzP6i3NlhtFyEhpcQxiUGxHZAGAEB3fIsSAFhQIleEn7rDEguG3eCFlLFBjKoQNeORtzyJGXp0oLhZd+tr3ny3WJKoc+pMXmQ349oqxTe9rwxsU0Aa0qPPfcYm73J9KMyqj1HM+8cNtbccZkMJwnIzr1GwBQbJ52EYW2tjxmozlPa/eJUfUmAucwYXUHVAOua5HXtvJ/zPTHZ9c8d54iQy/SyHvXfEOIK6abI4G6asb2N/MJF2orDEtPaocndYsKqDh3vOSwZBPDMndOjDcTUCYfqctGxXlUc6w1S31aR/cFszMnNhhZltaMTGCyMVA3RxrKYNpCQecfiy00fGDEtUhoeamJZHrOEy7kg9mGO9Lml7jCp+Gls5U7xtZrgx9uMH6LEH5DSHtGHLScYyjlS+geaGTglHjOV3lFotMdqTFYS9WxuLcBB4oKdxNMXNtSOmqcDLuYqF+iVcDwNWzLwyd8UMRSRlL3TPLJUTnTKmjjiRjKrKI2qH+jK/K2YORXd0dyc8BWlwexZnQ2am2UtSKDoHO6NGBkeEwdIUoHC5+wghhxhlMpvAyDHB7fJZRgC/OioRURpqf/mve9HOqZhxiYmx9/wBokhcU5N+xoNrJyhc1apLYKxQW5Crhbi93LtSYwCp2gkorEStFxNzixGHcYUE+7qrwTYGsMOJeHOwgscK4aJFrsKtEta6foaCAgGb3IZwf7hHDGBY44eHwLcRdfxLbNi3FhBGL+OGO+c+bcE1r2kTPhTEIfds3JBXNCsi7wsO0tGM8hJsYgJjF9Mg/oKewTqOwFptelSf0LtneVwox5FXU1coFqXBMtBQvnSjNMBaa0oiFLvBTYhXWfCltAKFuhVl8VWoq6iRTad6mRZzKCMM5CRV87ln/fU7L9OC92jMR3Un6LJhwxFaHJhLLBCBFyl/4TREiAsixhGMdojA3lrMzQcP3uSKd6jKkzVsdPJg+GZSicG7uRoTZct+oIWkEcVteiQX1Vg7VeZPyAUVAQeuGQa9OHs5bRuP6XUEOOZ4khwVr6SI8RqzGhiAS0AqFck9yKubZ6CvSAPPLLJUirgJfLZEj6QTlRxXHbIeu+Wkf+tOB2YkW/oQ4DqKNOSlOCnPc4t/XoOmGmWGD/SN7wG+UF4+AgWo56L3ZtvFQR6F95FEe8oBATQDINhV5rajfH+5Eo8mGBRAiGVcV3JdeyLxYbkKVQ==';

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
