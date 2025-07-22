import { strict as assert } from 'assert';
import { FileUtils } from '../src/utils/index';

describe('FileUtils', () => {
  describe('getSupportedExtensions', () => {
    it('should return supported extensions', () => {
      assert.deepEqual(FileUtils.getSupportedExtensions(), ['.py']);
    });
  });

  describe('isSupportedFile', () => {
    it('should return true for supported file', () => {
      assert.equal(FileUtils.isSupportedFile('test.py'), true);
    });
    it('should return false for unsupported file', () => {
      assert.equal(FileUtils.isSupportedFile('test.js'), false);
    });
  });

  describe('getLanguageFromExtension', () => {
    it('should return python for .py files', () => {
      assert.equal(FileUtils.getLanguageFromExtension('main.py'), 'python');
    });
    it('should return plaintext for unknown extension', () => {
      assert.equal(FileUtils.getLanguageFromExtension('main.txt'), 'plaintext');
    });
  });
}); 