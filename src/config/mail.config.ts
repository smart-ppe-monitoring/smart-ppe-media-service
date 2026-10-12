import { envConfig } from "./env.config";

export const mailConfig = {
  get appUrl(): string {
    const custom = process.env.APP_URL || envConfig.appUrl;
    const renderUrl =
      process.env.RENDER_EXTERNAL_URL || envConfig.renderExternalUrl;
    if (renderUrl && (!custom || custom.includes("localhost"))) {
      return renderUrl.replace(/\/+$/, "");
    }
    return (custom || "http://localhost:7777").replace(/\/+$/, "");
  },
  host: envConfig.mail.host,
  port: envConfig.mail.port,
  secure: envConfig.mail.secure,
  auth: {
    user: envConfig.mail.user,
    pass: envConfig.mail.pass,
  },
  from: envConfig.mail.from,
  get verificationUrl(): string {
    return `${this.appUrl}/api/v1/auth/verify-email`;
  },
  get resetPasswordUrl(): string {
    return `${this.appUrl}/api/v1/auth/reset-password`;
  },
  get resendApiKey(): string {
    return process.env.RESEND_API_KEY || envConfig.mail.resendApiKey;
  },
  get mailWebhookUrl(): string {
    return process.env.MAIL_WEBHOOK_URL || envConfig.mail.webhookUrl;
  },
  get isConfigured(): boolean {
    return Boolean(
      this.resendApiKey ||
      this.mailWebhookUrl ||
      (this.auth.user && this.auth.pass),
    );
  },
};
