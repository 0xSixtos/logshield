import { analyze } from './detector.js';
self.onmessage = ({ data }) => {
  try { self.postMessage({ id: data.id, result: analyze(data.text, data.options) }); }
  catch (error) { self.postMessage({ id: data.id, error: error.message }); }
};
