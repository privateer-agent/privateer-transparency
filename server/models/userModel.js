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
      // Store (native PaymentSheet) subs; 'play' for Google Play Billing subs;
      // 'apple' for App Store (StoreKit) subs. null for the default free plan
      // (no provider). Used to branch cancellation (Stripe API vs Play/App Store
      // deep-link) and to keep each provider's webhook from mutating another's
      // subscriptions.
      provider: {
        type: String,
        enum: ['stripe', 'play', 'apple', null],
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
      // App Store (StoreKit) state — populated only when provider === 'apple'.
      // The originalTransactionId is the stable subscription identity across
      // renewals (it never changes for the life of the subscription), so it's
      // what we bind to the account + dedupe on; the App Store Server
      // Notifications and re-validations key on it. Mirrors the role of
      // stripeSubscriptionId / play.purchaseToken. The shared fields above
      // (plan/status/startDate/endDate/autoRenew/billingInterval) stay
      // authoritative for entitlement regardless of provider.
      apple: {
        // Stable across renewals; sparse + unique via the index below so one
        // subscription can't bind to two accounts.
        originalTransactionId: String,
        // Most recent transactionId seen (per-period; changes each renewal).
        transactionId: String,
        // App Store product id (one product per tier+interval).
        productId: String,
        environment: String
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
    // Aggregate cloud bytes attributable to this user: every S3 object under
    // the `<userId>/` key prefix (images, videos, node/project files, thumbs)
    // plus Cargo + CargoVersion ciphertext, which is Mongo-resident but still
    // quota-bearing. Maintained by cloud-services on upload/delete and by
    // cargoController on write; `scripts/reconcile_cloud_storage_bytes.js`
    // recomputes it from S3 as ground truth when it drifts.
    //
    // Share assets (`shares/<token>/...`) are deliberately excluded — they are
    // uploaded via presigned URL, never charged, and never refunded.
    cloudStorageBytes: {
      type: Number,
      default: 0,
      min: 0
    },
    // When the account was first observed holding more than its tier allows,
    // or null while it fits. Derived state, not an event log: it is stamped by
    // whichever storage check notices first and cleared as soon as usage drops
    // back under the cap.
    //
    // Deliberately not driven off a Stripe downgrade webhook. A user can end up
    // over their cap without any billing event at all — the pass-tier mechanic
    // (entitlementService PASS_TIERS) promotes a free user holding $20 of top-up
    // to Navigator's 2 GB, and spending that balance down silently drops them to
    // Deckhand's 50 MB. Expiry and Apple/Play lapse are the same shape. Deriving
    // the state from `usage > cap` catches every path with no event plumbing.
    overQuotaSince: {
      type: Date,
      default: null
    },
    // When the over-quota notice was last emailed. Compared against
    // `overQuotaSince` so one notice goes out per episode: going back under the
    // cap clears the stamp above, and a later tier drop starts a fresh one.
    // Null for wallet accounts, which have no email address to reach.
    storageOverQuotaNotifiedAt: {
      type: Date,
      default: null
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
    // --- Aggregate analytics operational fields (see analyticsService) ---
    // Deliberately minimal: single overwritten scalars, never event trails.
    // Disclosed verbatim in the privacy policy — keep it that way.
    firstMessageAt: { type: Date, default: null },
    firstMediaGenAt: { type: Date, default: null },
    firstCargoAt: { type: Date, default: null },
    lastActiveAt: { type: Date, default: null },
    d1ReturnCounted: { type: Boolean, default: false },
    d7ReturnCounted: { type: Boolean, default: false },
    // Current-ISO-week message counter, hard-capped at the activation
    // threshold (3) so per-user volume beyond it is never stored.
    weeklyMsg: {
      week: { type: String, default: null },
      count: { type: Number, default: 0 }
    },
    // Preferred language for emails sent outside a request (e.g. the
    // hard-delete reminder cron), where there's no Accept-Language header to
    // read. Captured from the request language at registration. In-request
    // emails still prefer req.language; this is the fallback for cron jobs.
    emailLocale: { type: String, default: null },
    // X25519 public key (base64, 32 bytes) for the cloud outbox. Derived
    // deterministically from the account master key on a key-holding client and
    // published here so terminals (which hold NO key material) can seal results
    // TO it without ever being able to read them. Write-once/immutable after the
    // first set — see POST /api/outbox/pubkey — so a compromised terminal can't
    // swap in a key it controls. The matching private key never leaves clients.
    outboxPublicKey: { type: String, default: null },
    // Base64 Ed25519 signature over outboxPublicKey, made with the account signing key
    // (see client/services/accountSign.ts signOutboxKey). Stored opaquely — the server
    // never verifies it — and handed to terminals so they can reject a server that tries
    // to substitute a different outbox key (only the master-key holder can produce this
    // signature). Write-once alongside the key; backfillable once if an older client
    // published the key before signatures existed.
    outboxPublicKeySig: { type: String, default: null }
  },
  { timestamps: true }
);

// One Play purchase token binds to exactly one user. Sparse so the vast
// majority of users (no Play sub) aren't indexed and don't collide on null.
userSchema.index({ 'subscription.play.purchaseToken': 1 }, { unique: true, sparse: true });
userSchema.index({ 'subscription.apple.originalTransactionId': 1 }, { unique: true, sparse: true });

// The nightly over-quota notice sweep queries `overQuotaSince: { $ne: null }`.
// Partial rather than sparse: the field defaults to `null`, and a sparse index
// only skips documents where the field is *absent* — an explicit null is still
// indexed, so sparse would cover the whole collection and buy nothing. The
// $type filter indexes only accounts actually over their cap, which is the
// handful this sweep cares about.
userSchema.index(
  { overQuotaSince: 1 },
  { partialFilterExpression: { overQuotaSince: { $type: 'date' } } }
);

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
