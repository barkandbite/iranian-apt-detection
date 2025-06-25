# Contributing to Iranian APT Detection Rules

Thank you for your interest in contributing to this project. This document provides guidelines for contributing new rules, improving existing detections, and reporting issues.

## How to Contribute

### Reporting Issues
1. Check existing issues to avoid duplicates
2. Use descriptive titles (e.g., "False positive in rule 100922 for legitimate IIS activity")
3. Include:
   - Rule ID or file name
   - Description of the issue
   - Sample logs or traffic that triggered the issue
   - Expected vs actual behavior
   - Environment details (Wazuh version, OS, etc.)

### Submitting New Rules
1. Follow existing naming conventions:
   - Wazuh rules: Use next available ID in 100xxx range
   - Suricata rules: Use next available SID in 1000xxx range
2. Include MITRE ATT&CK mapping
3. Add appropriate severity levels
4. Test rules in a lab environment first
5. Document any dependencies or prerequisites

### Rule Format Standards

#### Wazuh Rules
```xml
<rule id="100xxx" level="14">
  <if_group>group_name</if_group>
  <field name="field_name">value</field>
  <description>Iranian APT: Clear description of detection</description>
  <mitre>
    <id>Txxxx</id>
  </mitre>
  <group>iranian_apt,category,</group>
</rule>
```

#### Suricata Rules
```
alert protocol $SOURCE_NET any -> $DEST_NET any (msg:"Iranian APT: Description"; flow:established; content:"pattern"; reference:cve,xxxx-xxxxx; classtype:attempted-admin; sid:1000xxx; rev:1;)
```

### Testing Requirements
1. Test against known malicious samples when possible
2. Verify no false positives in normal operations
3. Check performance impact
4. Test across different OS versions if applicable

## Code Style Guidelines

### XML Files
- Use 2-space indentation
- Keep line length under 120 characters
- Group related rules together
- Add comments for complex logic

### Documentation
- Use clear, technical language
- Avoid marketing terms or hyperbole
- Include practical examples
- Keep formatting consistent

## Pull Request Process

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/new-detection`)
3. Make your changes
4. Test thoroughly
5. Update documentation if needed
6. Submit pull request with:
   - Clear description of changes
   - Testing performed
   - Any new dependencies
   - Related issue numbers

## What We're Looking For

### High Priority Contributions
- New CVE detection rules for Iranian actors
- Improved behavioral detections
- Performance optimizations
- False positive reductions
- Documentation improvements

### Specific Needs
- Detection for new Iranian APT groups
- Cloud service exploitation patterns
- Container/Kubernetes attack detection
- MacOS/Linux specific rules
- Integration with additional SIEM platforms

## Security Considerations

- Never include actual malware samples
- Sanitize any real IP addresses or domains
- Don't expose sensitive infrastructure details
- Follow responsible disclosure for new vulnerabilities

## Recognition

Contributors will be acknowledged in release notes and the project README. Significant contributions may warrant co-authorship on related publications or presentations.

## Questions?

For questions about contributing, please open an issue with the "question" label or contact the maintainers through the repository's issue tracker.