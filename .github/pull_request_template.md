## Description

<!-- Brief description of the changes -->

## Type of Change

- [ ] Bug fix (non-breaking change that fixes an issue)
- [ ] New feature (non-breaking change that adds functionality)
- [ ] Breaking change (fix or feature that would cause existing functionality to not work as expected)
- [ ] Security fix (addresses a security vulnerability)
- [ ] Documentation update
- [ ] Refactoring (no functional changes)
- [ ] Build/CI changes

## Security Checklist

<!-- All items must be checked for PRs touching src/ -->

### Memory Safety
- [ ] All sensitive data uses zeroize-on-drop types
- [ ] All intermediate sensitive values are zeroed with `zeroize`
- [ ] No unbounded allocations from user input
- [ ] Array bounds checked before access

### Input Validation
- [ ] All public API functions validate inputs (null checks, size checks)
- [ ] Cryptographic inputs validated (public keys, scalars)

### Cryptographic Correctness
- [ ] Cryptographic crate APIs used correctly
- [ ] No custom cryptographic implementations
- [ ] MAC verified before decryption (if applicable)
- [ ] Constant-time comparisons for secrets (`subtle::ConstantTimeEq`)

### Error Handling
- [ ] All errors propagated correctly
- [ ] Cleanup performed on error paths
- [ ] No information leakage in error messages

### Build & Test
- [ ] No new compiler warnings (`cargo clippy -- -D warnings`)
- [ ] All existing tests pass
- [ ] New tests added for new functionality
- [ ] Tested on: <!-- List platforms tested -->

## Related Issues

<!-- Reference related issues: Fixes #123, Relates to #456 -->

## Additional Notes

<!-- Any additional context or notes for reviewers -->

---

**By submitting this PR, I confirm that:**
- [ ] I have read and followed the project contribution guidelines
- [ ] I have read and followed the [Security Policy](../SECURITY.md)
- [ ] My changes do not introduce security vulnerabilities
- [ ] I have not committed any sensitive data (keys, passwords, tokens)
