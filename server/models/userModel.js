/*
 * ───────────────────────────────────────────────────────────────────────────
 * Privateer — Transparency Excerpt (server)
 *
 * This file is published from Privateer's otherwise-closed server so anyone can
 * verify our core privacy claim: the server stores and forwards CIPHERTEXT
 * ONLY, never user plaintext, and routes AI inference exclusively to
 * Zero-Data-Retention providers.
 *
 * It is an EXCERPT, not a runnable build. Imports of modules that are NOT part
 * of this transparency repo (e.g. billing/pricing, entitlement/quota, S3/object
 * storage, email, rate limiting, Redis, Sentry wiring, logging) are left in
 * place so the code reads truthfully, but those modules are intentionally
 * omitted — they only ever see ciphertext, account IDs, and metadata, so they
 * add nothing to the privacy audit. Some such logic is stubbed inline with a
 * clearly marked "TRANSPARENCY REPO OMISSION" note.
 *
 * No secrets or credentials appear here; `process.env.*` reads reference public
 * variable NAMES only (documented in .env.example). See docs/E2EE_ARCHITECTURE.md.
 * ───────────────────────────────────────────────────────────────────────────
 */

const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const Subscription = require('./subscriptionModel');

// One-time signup grant credited to a brand-new account's subscription bucket
// (matches the free plan's $0.50 monthly allowance).
const SIGNUP_GRANT_USD = 0.50;

const userSchema = new mongoose.Schema(
  {
    email: {
      type: String,
      required: function() {
        return !this.solanaPublicKey;
      },
      unique: true,
      sparse: true,
      trim: true
    },
    profileImage: {
      type: String,
      default: null
    },
    password: {
      type: String,
      required: function() {
        return !this.solanaPublicKey;
      }
    },
    role: {
      type: String,
      enum: ['user', 'reader', 'admin'],
      default: 'reader',
      required: true
    },
    subscription: {
      plan: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Subscription'
      },
      startDate: Date,
      endDate: Date,
      status: {
        type: String,
        enum: ['active', 'cancelled', 'expired', 'pending', 'past_due', 'none'],
        default: 'pending'
      },
      // Which billing provider owns this subscription. 'stripe' for web / dApp
      // Store (native PaymentSheet) subs; 'play' for Google Play Billing subs.
      // null for the default free plan (no provider). Used to branch
      // cancellation (Stripe API vs Play deep-link) and to keep each provider's
      // webhook from mutating the other's subscriptions.
      provider: {
        type: String,
        enum: ['stripe', 'play', null],
        default: null
      },
      // Google Play Billing state — populated only when provider === 'play'.
      // Mirrors the role of stripeSubscriptionId/stripePriceId for Play. The
      // shared fields above (plan/status/startDate/endDate/autoRenew/
      // billingInterval) stay authoritative for entitlement regardless of
      // provider, so entitlementService needs no provider-specific logic.
      play: {
        // Current active purchase token (the Play subscription identity). Sparse
        // + unique via the index below so one token can't bind to two users.
        purchaseToken: String,
        // Play subscription product id (one product per paid tier).
        productId: String,
        // 'monthly' | 'annual' base plan within the product.
        basePlanId: String,
        // latestOrderId from the Play Developer API (for support/refund lookups).
        orderId: String,
        // Prior token in an upgrade/downgrade chain (Play replaces the token on
        // a plan change); retained for reconciliation against RTDN.
        linkedToken: String
      },
      stripeSubscriptionId: String,
      // Which Stripe price the user is currently billed on — used to tell
      // monthly/annual apart for the same plan tier.
      stripePriceId: String,
      billingInterval: {
        type: String,
        enum: ['month', 'year', null],
        default: null
      },
      // false while the subscription is set to cancel at period end — the
      // user keeps access until `endDate`, then `customer.subscription.deleted`
      // flips status to 'cancelled'. true means the sub will renew normally.
      autoRenew: {
        type: Boolean,
        default: true
      },
      // Set when the user has queued a downgrade. The active subscription keeps
      // running on the current price until `effectiveDate`; the Stripe schedule
      // then flips it to `toPlan` / `toPriceId`. Cleared by the webhook when the
      // schedule advances, or by an explicit cancel.
      pendingChange: {
        scheduleId: String,
        toPlan: { type: mongoose.Schema.Types.ObjectId, ref: 'Subscription' },
        toPriceId: String,
        toBillingInterval: {
          type: String,
          enum: ['month', 'year', null],
          default: null
        },
        effectiveDate: Date
      }
    },
    stripeCustomerId: {
      type: String,
      sparse: true
    },
    billingEmail: {
      type: String,
      trim: true
    },
    // Subscription credit — granted by an active subscription on each billing
    // cycle. Reset (not incremented) on renewal; unused balance does not roll
    // over. Drained before topUpCreditUsd.
    subscriptionCreditUsd: {
      type: Number,
      default: 0,
      min: 0
    },
    // Top-up credit — pay-as-you-go USD purchased via Stripe or Solana/USDC.
    // Persists across cycles; drained only after subscriptionCreditUsd is empty.
    topUpCreditUsd: {
      type: Number,
      default: 0,
      min: 0
    },
    // Held against in-flight expensive jobs (video gen, etc) via reservationService.
    // Funds are moved here from subscriptionCreditUsd/topUpCreditUsd at reserve time
    // and either consumed (settle) or returned to source buckets (release/refund).
    // NOT included in hasEnoughBalance/totalCreditUsd — from the user's POV these
    // funds are already spent until the job resolves.
    reservedCreditUsd: {
      type: Number,
      default: 0,
      min: 0
    },
    // Tracks whether the one-time $0.50 signup grant has been credited.
    signupGrantApplied: {
      type: Boolean,
      default: false
    },
    // Legacy flag for the one-time $10 referral/share credit bonus. The waitlist
    // that previously granted it has been removed; retained for historical data
    // and a future referral source.
    referralBonusApplied: {
      type: Boolean,
      default: false
    },
    // Aggregate S3 bytes attributable to this user (ProjectFile + LibraryVideo
    // + any other cloud-stored binaries). Maintained by cloud-services on
    // upload/delete; backfilled by the migration.
    cloudStorageBytes: {
      type: Number,
      default: 0,
      min: 0
    },
    solanaPublicKey: {
      type: String,
      sparse: true,
      unique: true
    },
    // E2EE master key, AES-256-GCM-wrapped under a KEK derived from the user's
    // password (Argon2id) or wallet signature (HKDF). Format: base64 of IV||ciphertext||tag.
    // Server stores ciphertext only — it never sees the master key or the KEK.
    wrappedMasterKey: {
      type: String,
      default: null
    },
    // How the KEK that unwraps wrappedMasterKey is produced.
    //   'password' — Argon2id over the user's password with kdfSalt + kdfParams
    //   'wallet'   — HKDF-SHA256 over the wallet's signature of the v2
    //                 vault-key message "Privateer vault key v2 for <pubkey>"
    kekSource: {
      type: String,
      enum: ['password', 'wallet', null],
      default: null
    },
    // Argon2id salt (base64, 16 bytes). Password users only.
    kdfSalt: {
      type: String,
      default: null
    },
    // Argon2id parameters. Password users only.
    //   { algorithm: 'argon2id', m: <memKiB>, t: <iterations>, p: <parallelism> }
    kdfParams: {
      type: mongoose.Schema.Types.Mixed,
      default: null
    },
    // Version of the wallet vault-key message that was signed to derive the
    // KEK. Always 2 ("Privateer vault key v2 for <pubkey-hex>") — v1 was never
    // released, so there is no legacy account class. Wallet users only; null
    // for password users.
    kekMessageVersion: {
      type: Number,
      enum: [2, null],
      default: null
    },
    accountStatus: {
      type: String,
      enum: ['active', 'grace_period', 'deleted'],
      default: 'active'
    },
    deletionRequestedAt: {
      type: Date,
      default: null
    },
    hardDeleteAt: {
      type: Date,
      default: null
    },
    isEmailVerified: { type: Boolean, default: false },
    emailVerificationToken: String,
    emailVerificationExpires: Date,
    // Preferred language for emails sent outside a request (e.g. the
    // hard-delete reminder cron), where there's no Accept-Language header to
    // read. Captured from the request language at registration. In-request
    // emails still prefer req.language; this is the fallback for cron jobs.
    emailLocale: { type: String, default: null }
  },
  { timestamps: true }
);

// One Play purchase token binds to exactly one user. Sparse so the vast
// majority of users (no Play sub) aren't indexed and don't collide on null.
userSchema.index({ 'subscription.play.purchaseToken': 1 }, { unique: true, sparse: true });

userSchema.pre('save', async function(next) {
  if (this.password && (this.isModified('password') || this.isNew)) {
    try {
      const salt = await bcrypt.genSalt(parseInt(process.env.BCRYPT_ROUNDS) || 12);
      this.password = await bcrypt.hash(this.password, salt);
    } catch (error) {
      return next(error);
    }
  }
  next();
});

userSchema.pre('save', async function(next) {
  try {
    if (this.isNew || !this.subscription.plan) {
      const freePlan = await Subscription.findOne({ tier: 'free', isActive: true });

      if (freePlan) {
        this.subscription = {
          plan: freePlan._id,
          startDate: new Date(),
          endDate: new Date(Date.now() + freePlan.duration * 24 * 60 * 60 * 1000),
          status: 'active',
          autoRenew: true
        };
      }
    }

    // Signup grant — credited to subscription bucket. Matches the free plan's
    // monthly $0.50 allowance; resets on the next subscription cycle.
    if (this.isNew && !this.signupGrantApplied) {
      this.subscriptionCreditUsd = (this.subscriptionCreditUsd || 0) + SIGNUP_GRANT_USD;
      this.signupGrantApplied = true;
    }
    next();
  } catch (error) {
    next(error);
  }
});

userSchema.methods.comparePassword = async function (password) {
  try {
    return await bcrypt.compare(password, this.password);
  } catch (error) {
    throw error;
  }
};

userSchema.methods.hasEnoughBalance = function(amountUsd) {
  return (this.subscriptionCreditUsd + this.topUpCreditUsd) >= amountUsd;
};

userSchema.methods.totalCreditUsd = function() {
  return (this.subscriptionCreditUsd || 0) + (this.topUpCreditUsd || 0);
};

userSchema.methods.hasActiveSubscription = function() {
  if (!this.subscription.plan) return false;
  const now = new Date();
  return (
    this.subscription.status === 'active' &&
    this.subscription.endDate > now
  );
};

userSchema.set('toJSON', { virtuals: true });
userSchema.set('toObject', { virtuals: true });

const User = mongoose.model('User', userSchema);

module.exports = User;
module.exports.SIGNUP_GRANT_USD = SIGNUP_GRANT_USD;
