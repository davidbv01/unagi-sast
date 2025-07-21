import { strict as assert } from 'assert';

describe('Sample Test Suite', () => {
  it('should add numbers correctly', () => {
    function add(a: number, b: number): number {
      return a + b;
    }
    assert.equal(add(2, 3), 5);
    assert.equal(add(-1, 1), 0);
  });
}); 