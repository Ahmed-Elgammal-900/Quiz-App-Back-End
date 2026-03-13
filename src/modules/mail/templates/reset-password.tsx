import * as React from 'react';
import {
  Body,
  Button,
  Container,
  Head,
  Heading,
  Html,
  Preview,
  Section,
  Text,
  Hr,
  Font,
  Link,
  Column,
  Row,
} from '@react-email/components';

interface ResetPasswordEmailProps {
  resetUrl: string;

  appName?: string;

  expiryMins?: number;

  recipientName?: string;

  primaryColor?: string;
}

export const ResetPasswordEmail = ({
  resetUrl,
  appName = 'Quizzer',
  expiryMins = 15,
  recipientName = '',
  primaryColor = '#0f1fd1',
}: ResetPasswordEmailProps) => {
  const previewText = `Reset your ${appName} password`;
  const initial = appName.charAt(0).toUpperCase();

  return (
    <Html lang="en" dir="ltr">
      <Head>
        <Font
          fontFamily="Georgia"
          fallbackFontFamily="Times New Roman"
          webFont={undefined}
          fontWeight={400}
          fontStyle="normal"
        />
        <title>{previewText}</title>
      </Head>

      <Preview>{previewText}</Preview>

      <Body style={styles.body}>
        <Container style={styles.container}>
          {/* ── Top accent stripe ── */}
          <Section
            style={{ ...styles.accentStripe, backgroundColor: primaryColor }}
          />

          {/* ── Main content ── */}
          <Section style={styles.content}>
            {/* ── Brand mark — Row/Column renders as table/td for proper vertical align ── */}
            <Row style={styles.brandRow}>
              {/* Logo column — fixed width */}
              <Column style={styles.logoColumn}>
                <div
                  style={{ ...styles.logoMark, backgroundColor: primaryColor }}
                >
                  <span style={styles.logoInitial}>{initial}</span>
                </div>
              </Column>

              {/* App name column */}
              <Column style={styles.brandNameColumn}>
                <Text style={{ ...styles.brandName, color: primaryColor }}>
                  {appName}
                </Text>
              </Column>
            </Row>

            {/* Lock icon */}
            <Text style={styles.iconEmoji}>🔒</Text>

            {/* Heading */}
            <Heading as="h1" style={styles.heading}>
              Reset your password
            </Heading>

            {/* Body copy */}
            <Text style={styles.bodyText}>
              {recipientName ? `Hi ${recipientName}, we` : 'We'} received a
              request to reset the password for your{' '}
              <strong style={{ color: '#1a1a1a' }}>{appName}</strong> account.
              Click the button below to choose a new password.
            </Text>

            <Text style={styles.expiryText}>
              ⏱ This link expires in {expiryMins} minute
              {expiryMins !== 1 ? 's' : ''}
            </Text>

            {/* ── CTA Button ── */}
            <Section style={styles.buttonSection}>
              <Button
                href={resetUrl}
                style={{ ...styles.button, backgroundColor: primaryColor }}
              >
                Reset Password →
              </Button>
            </Section>

            {/* Fallback URL */}
            <Text style={styles.fallbackLabel}>
              Or copy and paste this link into your browser:
            </Text>
            <Section style={styles.urlBox}>
              <Text style={styles.urlText}>
                <Link
                  href={resetUrl}
                  style={{ ...styles.urlLink, color: primaryColor }}
                >
                  {resetUrl}
                </Link>
              </Text>
            </Section>

            {/* Security notice */}
            <Section style={styles.noticeSection}>
              <Text style={styles.noticeText}>
                If you didn&apos;t request a password reset, please ignore this
                email immediately. Your password will remain unchanged.
              </Text>
            </Section>
          </Section>
        </Container>
      </Body>
    </Html>
  );
};

export default ResetPasswordEmail;

const styles: Record<string, React.CSSProperties> = {
  body: {
    backgroundColor: '#eee',
    fontFamily: "Georgia, 'Times New Roman', Times, serif",
    margin: '0',
    padding: '40px 0',
  },
  container: {
    backgroundColor: 'white',
    borderRadius: '6px',
    maxWidth: '560px',
    margin: '0 auto',
    overflow: 'hidden',
  },
  iconEmoji: {
    fontSize: '40px',
    marginTop: '0',
    marginBottom: '28px',
    marginLeft: '0',
    marginRight: '0',
  },
  accentStripe: {
    height: '4px',
    width: '100%',
  },
  content: {
    paddingTop: '48px',
    paddingBottom: '40px',
    paddingLeft: '52px',
    paddingRight: '52px',
  },
  brandRow: {
    marginBottom: '36px',
  },
  logoColumn: {
    width: '44px',
    verticalAlign: 'middle',
  },
  logoMark: {
    width: '36px',
    height: '36px',
    borderRadius: '8px',
    textAlign: 'center',
    verticalAlign: 'middle',
    display: 'table',
  },
  logoInitial: {
    display: 'table-cell',
    verticalAlign: 'middle',
    textAlign: 'center',
    color: '#ffffff',
    fontSize: '18px',
    fontWeight: '800',
    fontFamily: "Georgia, 'Times New Roman', Times, serif",
    letterSpacing: '-0.5px',
    lineHeight: '1',
  },
  brandNameColumn: {
    verticalAlign: 'middle',
  },
  brandName: {
    display: 'inline',
    fontSize: '15px',
    fontWeight: '700',
    letterSpacing: '0.3px',
    marginTop: '0',
    marginBottom: '0',
    marginLeft: '0',
    marginRight: '0',
  },

  // Typography
  heading: {
    fontSize: '26px',
    fontWeight: '700',
    color: '#1a1a1a',
    lineHeight: '1.25',
    letterSpacing: '-0.4px',
    marginTop: '0',
    marginBottom: '16px',
    marginLeft: '0',
    marginRight: '0',
  },
  bodyText: {
    fontSize: '15px',
    color: '#666666',
    lineHeight: '1.75',
    marginTop: '0',
    marginBottom: '8px',
    marginLeft: '0',
    marginRight: '0',
  },
  expiryText: {
    fontSize: '13px',
    color: '#aaaaaa',
    lineHeight: '1.6',
    fontFamily: "'Courier New', Courier, monospace",
    letterSpacing: '0.3px',
    marginTop: '0',
    marginBottom: '32px',
    marginLeft: '0',
    marginRight: '0',
  },

  // CTA Button
  buttonSection: {
    marginBottom: '28px',
    textAlign: 'left' as const,
  },
  button: {
    color: '#ffffff',
    fontSize: '14px',
    fontWeight: '600',
    fontFamily: "Georgia, 'Times New Roman', Times, serif",
    letterSpacing: '0.4px',
    paddingTop: '14px',
    paddingBottom: '14px',
    paddingLeft: '32px',
    paddingRight: '32px',
    borderRadius: '5px',
    textDecoration: 'none',
    display: 'inline-block',
  },

  // Fallback URL
  fallbackLabel: {
    fontSize: '12px',
    color: '#aaaaaa',
    fontFamily: "'Courier New', Courier, monospace",
    letterSpacing: '0.3px',
    marginTop: '0',
    marginBottom: '10px',
    marginLeft: '0',
    marginRight: '0',
  },
  urlBox: {
    backgroundColor: '#e6e6e6',
    borderRadius: '4px',
    paddingTop: '12px',
    paddingBottom: '12px',
    paddingLeft: '16px',
    paddingRight: '16px',
    marginBottom: '32px',
    border: '1px solid #d6d6d6',
  },
  urlText: {
    margin: '0',
    fontSize: '12px',
    wordBreak: 'break-all' as const,
    fontFamily: "'Courier New', Courier, monospace",
  },
  urlLink: {
    textDecoration: 'underline',
    wordBreak: 'break-all' as const,
  },

  // Security notice
  noticeSection: {
    borderLeft: '3px solid #d6d6d6',
    paddingLeft: '16px',
    marginBottom: '36px',
  },
  noticeText: {
    fontSize: '13px',
    color: '#999999',
    lineHeight: '1.7',
    margin: '0',
  },
};
