/**
 * deliveryEngine.js  (v2 — tiered zone pricing)
 * ─────────────────────────────────────────────────────────────────────────────
 * Pure, stateless delivery calculation engine.
 * No DB access — all data is passed in as arguments.
 *
 * Rule priority (first match wins):
 *  1. PRODUCT RULE  — free_delivery_enabled=true AND line total >= min amount → FREE
 *  2. ZONE TIER     — look up zone, find matching cart-total range → tier charge
 * ─────────────────────────────────────────────────────────────────────────────
 */

/**
 * Default zone tiers (used when DB has no settings yet).
 * @type {Record<string, Array<{min:number, max:number|null, charge:number}>>}
 */
const DEFAULT_ZONES = {
  'Dhaka': [
    { min: 0,    max: 500,  charge: 60 },
    { min: 501,  max: 1000, charge: 40 },
    { min: 1001, max: null, charge: 0  },
  ],
  'Outside Dhaka': [
    { min: 0,    max: 500,  charge: 120 },
    { min: 501,  max: 1000, charge: 80  },
    { min: 1001, max: null, charge: 50  },
  ],
};

/**
 * Determine the zone name from checkout form inputs.
 * @param {string} deliveryLocation  e.g. 'Dhaka' | 'Outside Dhaka'
 * @param {string} city
 * @param {string} address
 * @param {string[]} zoneNames  - known zone names from settings
 * @returns {string} matched zone name or first zone as fallback
 */
function resolveZone(deliveryLocation = '', city = '', address = '', zoneNames = []) {
  // Exact match on deliveryLocation first
  if (zoneNames.includes(deliveryLocation)) return deliveryLocation;

  // Fuzzy match: check if city/address contains a zone keyword
  const loc = `${city} ${address}`.toLowerCase();
  for (const name of zoneNames) {
    if (loc.includes(name.toLowerCase())) return name;
  }

  // Dhaka keyword detection
  if (loc.includes('dhaka') || deliveryLocation.toLowerCase().includes('dhaka')) {
    return zoneNames.find(n => n.toLowerCase().includes('dhaka') && !n.toLowerCase().includes('outside')) || zoneNames[0];
  }

  return zoneNames[0] || 'Dhaka';
}

/**
 * Find the applicable charge for a given cart total within a zone's tiers.
 * @param {Array<{min:number, max:number|null, charge:number}>} tiers
 * @param {number} cartTotal
 * @returns {number}
 */
function getZoneCharge(tiers = [], cartTotal = 0) {
  const sorted = [...tiers].sort((a, b) => a.min - b.min);
  for (const tier of sorted) {
    const withinMin = cartTotal >= tier.min;
    const withinMax = tier.max === null || cartTotal <= tier.max;
    if (withinMin && withinMax) return tier.charge;
  }
  // Fallback: last tier
  return sorted.length > 0 ? sorted[sorted.length - 1].charge : 0;
}

/**
 * Compute the effective line total for a cart item.
 * @param {{price:number, quantity?:number}} item
 * @returns {number}
 */
function lineTotal(item) {
  return (item.price || 0) * (parseInt(item.quantity) || 1);
}

/**
 * Calculate order subtotal from cart items.
 * @param {Array<{price:number, quantity?:number}>} cartItems
 * @returns {number}
 */
function computeSubtotal(cartItems = []) {
  return cartItems.reduce((sum, item) => sum + lineTotal(item), 0);
}

/**
 * Core delivery computation — v2 with tiered zone pricing.
 *
 * @param {object} opts
 * @param {Array}  opts.cartItems         - enriched cart items (must include free_delivery_* fields)
 * @param {object} opts.zoneTiers         - { "Dhaka": [{min,max,charge},...], "Outside Dhaka": [...] }
 * @param {string} opts.deliveryLocation  - 'Dhaka' | 'Outside Dhaka' | ''
 * @param {string} [opts.city]
 * @param {string} [opts.address]
 *
 * @returns {{
 *   charge:          number,
 *   isFree:          boolean,
 *   reason:          'product_free_delivery' | 'zone_tier' | null,
 *   freeRuleProduct: string | null,
 *   resolvedZone:    string,
 *   hints:           Array<{productId,productTitle,amountNeeded,currentSpend,minAmount}>,
 * }}
 */
function computeDelivery({ cartItems = [], zoneTiers = {}, deliveryLocation = '', city = '', address = '' }) {
  const zones      = Object.keys(zoneTiers).length ? zoneTiers : DEFAULT_ZONES;
  const zoneNames  = Object.keys(zones);
  const zone       = resolveZone(deliveryLocation, city, address, zoneNames);
  const cartTotal  = computeSubtotal(cartItems);

  // ── Rule 1: Per-product free delivery ───────────────────────────────────
  const freeProduct = cartItems.find(item =>
    item.free_delivery_enabled === true &&
    lineTotal(item) >= (item.free_delivery_min_amount || 0)
  );

  if (freeProduct) {
    return {
      charge: 0,
      isFree: true,
      reason: 'product_free_delivery',
      freeRuleProduct: freeProduct.title || null,
      resolvedZone: zone,
      hints: [],
    };
  }

  // ── Build "almost-free" hints for products that nearly qualify ──────────
  const hints = cartItems
    .filter(item =>
      item.free_delivery_enabled === true &&
      lineTotal(item) < (item.free_delivery_min_amount || 0)
    )
    .map(item => ({
      productId:    item.productId || (item._id ? item._id.toString() : ''),
      productTitle: item.title || 'this product',
      minAmount:    item.free_delivery_min_amount,
      currentSpend: lineTotal(item),
      amountNeeded: (item.free_delivery_min_amount || 0) - lineTotal(item),
    }));

  // ── Rule 2: Zone tier charge ─────────────────────────────────────────────
  const tiers  = zones[zone] || zones[zoneNames[0]] || [];
  const charge = getZoneCharge(tiers, cartTotal);

  return {
    charge,
    isFree: charge === 0,
    reason: 'zone_tier',
    freeRuleProduct: null,
    resolvedZone: zone,
    hints,
  };
}

/**
 * Validate zone tiers structure sent by admin.
 * @param {any} zones
 * @returns {{ valid: boolean, error?: string }}
 */
function validateZoneTiers(zones) {
  if (!zones || typeof zones !== 'object' || Array.isArray(zones)) {
    return { valid: false, error: 'zones must be an object' };
  }
  for (const [zoneName, tiers] of Object.entries(zones)) {
    if (!Array.isArray(tiers) || tiers.length === 0) {
      return { valid: false, error: `Zone "${zoneName}" must have at least one tier` };
    }
    for (const tier of tiers) {
      if (typeof tier.min !== 'number' || tier.min < 0) {
        return { valid: false, error: `Zone "${zoneName}": tier min must be a non-negative number` };
      }
      if (tier.max !== null && (typeof tier.max !== 'number' || tier.max < tier.min)) {
        return { valid: false, error: `Zone "${zoneName}": tier max must be >= min or null` };
      }
      if (typeof tier.charge !== 'number' || tier.charge < 0) {
        return { valid: false, error: `Zone "${zoneName}": tier charge must be a non-negative number` };
      }
    }
  }
  return { valid: true };
}

module.exports = {
  computeDelivery,
  computeSubtotal,
  getZoneCharge,
  resolveZone,
  validateZoneTiers,
  lineTotal,
  DEFAULT_ZONES,
};
