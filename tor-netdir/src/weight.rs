//! Functions for applying the correct weights to relays when choosing
//! a relay at random.
//!
//! The weight to use when picking a relay depends on several factors:
//!
//! - The relay's *apparent bandwidth*.  (This is ideally measured by a set of
//!   bandwidth authorities, but if no bandwidth authorities are running (as on
//!   a test network), we might fall back either to relays' self-declared
//!   values, or we might treat all relays as having equal bandwidth.)
//! - The role that we're selecting a relay to play.  (See [`WeightRole`]).
//! - The flags that a relay has in the consensus, and their scarcity.  If a
//!   relay provides particularly scarce functionality, we might choose not to
//!   use it for other roles, or to use it less commonly for them.

use crate::params::{NetParameters, Param};
use tor_netdoc::doc::netstatus::{MdConsensus, MdConsensusRouterStatus, NetParams, RouterWeight};

/// Helper: Calculate the function we should use to find initial relay
/// bandwidths.
fn pick_bandwidth_fn<'a, I>(mut weights: I) -> BandwidthFn
where
    I: Clone + Iterator<Item = &'a RouterWeight>,
{
    let has_measured = weights.clone().any(|w| w.is_measured());
    let has_nonzero = weights.clone().any(|w| w.is_nonzero());
    let has_nonzero_measured = weights.any(|w| w.is_measured() && w.is_nonzero());

    if !has_nonzero {
        // If every value is zero, we should just pretend everything has
        // bandwidth == 1.
        BandwidthFn::Uniform
    } else if !has_measured {
        // If there are no measured values, then we can look at unmeasured
        // weights.
        BandwidthFn::IncludeUnmeasured
    } else if has_nonzero_measured {
        // Otherwise, there are measured values; we should look at those only, if
        // any of them is nonzero.
        BandwidthFn::MeasuredOnly
    } else {
        // This is a bit of an ugly case: We have measured values, but they're
        // all zero.  If this happens, the bandwidth authorities exist but they
        // very confused: we should fall back to uniform wrighting.
        BandwidthFn::Uniform
    }
}

/// Internal: how should we find the base bandwidth of each relay?  This
/// value is global over a whole directory, and depends on the bandwidth
/// weights in the consensus.
#[derive(Copy, Clone, Debug, PartialEq)]
enum BandwidthFn {
    /// There are no weights at all in the consensus: weight every
    /// relay as 1.
    Uniform,
    /// There are no measured weights in the consensus: count
    /// unmeasured weights as the weights for relays.
    IncludeUnmeasured,
    /// There are measured relays in the consensus; only use those.
    MeasuredOnly,
}

impl BandwidthFn {
    /// Apply this function to the measured or unmeasured bandwidth
    /// of a single router.
    fn apply(&self, w: &RouterWeight) -> u32 {
        use BandwidthFn::*;
        use RouterWeight::*;
        match (self, w) {
            (Uniform, _) => 1,
            (IncludeUnmeasured, Unmeasured(u)) => *u,
            (IncludeUnmeasured, Measured(m)) => *m,
            (MeasuredOnly, Unmeasured(_)) => 0,
            (MeasuredOnly, Measured(m)) => *m,
            (_, _) => 0,
        }
    }
}

/// Possible ways to weight routers when selecting them a random.
///
/// Routers are weighted by a function of their bandwidth that
/// depends on how scarce that "kind" of bandwidth is.  For
/// example, if Exit bandwidth is rare, then Exits should be
/// less likely to get chosen for the middle hop of a path.
#[derive(Clone, Debug, Copy)]
#[non_exhaustive]
pub enum WeightRole {
    /// Selecting a node to use as a guard
    Guard,
    /// Selecting a node to use as a middle relay in a circuit.
    Middle,
    /// Selecting a node to use to deliver traffic to the internet.
    Exit,
    /// Selecting a node for a one-hop BEGIN_DIR directory request.
    BeginDir,
    /// Selecting a node with no additional weight beyond its bandwidth.
    Unweighted,
}

/// Description for how to weight a single kind of relay for each WeightRole.
#[derive(Clone, Debug, Copy)]
struct RelayWeight {
    /// How to weight this kind of relay when picking a guard node.
    as_guard: u32,
    /// How to weight this kind of relay when picking a middle node.
    as_middle: u32,
    /// How to weight this kind of relay when picking a exit node.
    as_exit: u32,
    /// How to weight this kind of relay when picking a one-hop BEGIN_DIR.
    as_dir: u32,
}

impl std::ops::Mul<u32> for RelayWeight {
    type Output = Self;
    fn mul(self, rhs: u32) -> Self {
        RelayWeight {
            as_guard: self.as_guard * rhs,
            as_middle: self.as_middle * rhs,
            as_exit: self.as_exit * rhs,
            as_dir: self.as_dir * rhs,
        }
    }
}
impl std::ops::Div<u32> for RelayWeight {
    type Output = Self;
    fn div(self, rhs: u32) -> Self {
        RelayWeight {
            as_guard: self.as_guard / rhs,
            as_middle: self.as_middle / rhs,
            as_exit: self.as_exit / rhs,
            as_dir: self.as_dir / rhs,
        }
    }
}

impl RelayWeight {
    /// Return the largest weight that we give for this kind of relay.
    fn max_weight(&self) -> u32 {
        [self.as_guard, self.as_middle, self.as_exit, self.as_dir]
            .iter()
            .max()
            .copied()
            .unwrap() // unwrap is safe since the input is nonempty.
    }
    /// Return the weight we should give this kind of relay's
    /// bandwidth for a given role.
    fn for_role(&self, role: WeightRole) -> u32 {
        match role {
            WeightRole::Guard => self.as_guard,
            WeightRole::Middle => self.as_middle,
            WeightRole::Exit => self.as_exit,
            WeightRole::BeginDir => self.as_dir,
            WeightRole::Unweighted => 1,
        }
    }
}

/// A kind of relay, for the purposes of selecting a relay by weight.
///
/// Relays can have or lack the Guard flag, the Exit flag, and the V2Dir flag.
/// All together, this makes 8 kinds of relays.
// TODO: use bitflags here?
struct WeightKind(u8);
/// Flag in weightkind for Guard nodes.
const FLG_GUARD: u8 = 1 << 0;
/// Flag in weightkind for Exit nodes.
const FLG_EXIT: u8 = 1 << 1;
/// Flag in weightkind for V2Dir nodes.
const FLG_DIR: u8 = 1 << 2;

impl WeightKind {
    /// Return the appropriate WeightKind for a relay.
    fn for_rs(rs: &MdConsensusRouterStatus) -> Self {
        let mut r = 0;
        if rs.is_flagged_guard() {
            r |= FLG_GUARD;
        }
        if rs.is_flagged_exit() {
            r |= FLG_EXIT;
        }
        if rs.is_flagged_v2dir() {
            r |= FLG_DIR;
        }
        WeightKind(r)
    }
    /// Return the index to use for this kind of a relay within a WeightSet.
    fn idx(self) -> usize {
        self.0 as usize
    }
}

/// Information derived from a consensus to use when picking relays by
/// weighted bandwidth.
#[derive(Debug, Clone)]
pub(crate) struct WeightSet {
    /// How to find the bandwidth to use when picking a router by weighted
    /// bandwidth.
    ///
    /// (This tells us us whether to count unmeasured relays, whether
    /// to look at bandwidths at all, etc.)
    bandwidth_fn: BandwidthFn,
    /// Number of bits that we need to right-shift our weighted products
    /// so that their sum won't overflow u64::MAX.
    shift: u8,
    /// A set of RelayWeight values, indexed by [`WeightKind::idx`], used
    /// to weight different kinds of relays.
    w: [RelayWeight; 8],
}

impl WeightSet {
    /// Find the actual 64-bit weight to use for a given routerstatus when
    /// considering it for a given role.
    pub(crate) fn weight_rs_for_role(&self, rs: &MdConsensusRouterStatus, role: WeightRole) -> u64 {
        self.weight_bw_for_role(WeightKind::for_rs(&rs), rs.weight(), role)
    }

    /// Find the 64-bit weight to report for a relay of `kind` whose weight in
    /// the consensus is `router_weight` when using it for `role`.
    fn weight_bw_for_role(
        &self,
        kind: WeightKind,
        router_weight: &RouterWeight,
        role: WeightRole,
    ) -> u64 {
        let ws = &self.w[kind.idx()];

        let router_bw = self.bandwidth_fn.apply(router_weight);
        // Note a subtlety here: we multiply the two values _before_
        // we shift, to improve accuracy.  We know that this will be
        // safe, since the inputs are both u32, and so cannot overflow
        // a u64.
        let router_weight = (router_bw as u64) * (ws.for_role(role) as u64);
        router_weight >> self.shift
    }

    /// Compute the correct WeightSet for a provided MdConsensus.
    pub(crate) fn from_consensus(consensus: &MdConsensus, params: &NetParameters) -> Self {
        let bandwidth_fn = pick_bandwidth_fn(consensus.routers().iter().map(|rs| rs.weight()));
        let weight_scale = params.get(Param::BwWeightScale);
        let total_bw = consensus
            .routers()
            .iter()
            .map(|rs| bandwidth_fn.apply(rs.weight()) as u64)
            .sum();
        let p = consensus.bandwidth_weights();

        Self::from_parts(bandwidth_fn, total_bw, weight_scale, p)
    }

    /// Compute the correct WeightSet given a bandwidth function, a
    /// weight-scaling parameter, a total amount of bandwidth for all
    /// relays in the consensus, and a set of bandwidth parameters.
    fn from_parts(
        bandwidth_fn: BandwidthFn,
        total_bw: u64,
        weight_scale: i32,
        p: &NetParams<i32>,
    ) -> Self {
        /// Find a single RelayWeight, given the names that its bandwidth
        /// parameters have. The `g` parameter is the weight as a guard, the
        /// `m` parameter is the weight as a middle node, the `e` parameter is
        /// the weight as an exit, and the `d` parameter is the weight as a
        /// directory.
        #[allow(clippy::many_single_char_names)]
        fn single(p: &NetParams<i32>, g: &str, m: &str, e: &str, d: &str) -> RelayWeight {
            RelayWeight {
                as_guard: w_param(p, g),
                as_middle: w_param(p, m),
                as_exit: w_param(p, e),
                as_dir: w_param(p, d),
            }
        }

        assert!(weight_scale >= 0);
        let weight_scale = weight_scale as u32;

        // For non-V2Dir nodes, we have names for most of their weights.
        //
        // (There is no Wge, since we only use Guard nodes as guards.  By the
        // same logic, Wme has no reason to exist, but according to the spec it
        // does.)
        let w_none = single(p, "Wgm", "Wmm", "Wem", "Wbm");
        let w_guard = single(p, "Wgg", "Wmg", "Weg", "Wbg");
        let w_exit = single(p, "---", "Wme", "Wee", "Wbe");
        let w_both = single(p, "Wgd", "Wmd", "Wed", "Wbd");

        // Note that the positions of the elements in this array need to
        // match the values returned by WeightKind.as_idx().
        let w = [
            w_none,
            w_guard,
            w_exit,
            w_both,
            // The V2Dir values are the same as the non-V2Dir values, except
            // each is multiplied by an additional factor.
            //
            // (We don't need to check for overflow here, since the
            // authorities make sure that the inputs don't get too big.)
            (w_none * w_param(p, "Wmb")) / weight_scale,
            (w_guard * w_param(p, "Wgb")) / weight_scale,
            (w_exit * w_param(p, "Web")) / weight_scale,
            (w_both * w_param(p, "Wdb")) / weight_scale,
        ];

        // This is the largest weight value.
        // The unwrap() is safe because `w` is nonempty.
        let w_max = w.iter().map(RelayWeight::max_weight).max().unwrap();

        // We want "shift" such that (total * w_max) >> shift <= u64::max
        let shift = calculate_shift(total_bw, w_max as u64) as u8;

        WeightSet {
            bandwidth_fn,
            shift,
            w,
        }
    }
}

/// The value to return if a weight parameter is absent.
///
/// (If there are no weights at all, then it's correct to set them all to 1,
/// and just use the bandwidths.  If _some_ are present and some are absent,
/// then the spec doesn't say what to do, but this behavior appears
/// reasonable.)
const DFLT_WEIGHT: i32 = 1;

/// Return the weight param named 'kwd' in p.
///
/// Returns DFLT_WEIGHT if there is no such parameter, and 0
/// if `kwd` is "---".
fn w_param(p: &NetParams<i32>, kwd: &str) -> u32 {
    if kwd == "---" {
        0
    } else {
        clamp_to_pos(*p.get(kwd).unwrap_or(&DFLT_WEIGHT))
    }
}

/// If `inp` is less than 0, return 0.  Otherwise return `inp` as a u32.
fn clamp_to_pos(inp: i32) -> u32 {
    // (The spec says that we might encounter negative values here, though
    // we never actually generate them, and don't plan to generate them.)
    if inp < 0 {
        0
    } else {
        inp as u32
    }
}

/// Compute a 'shift' value such that `(a * b) >> shift` will be contained
/// inside 64 bits.
fn calculate_shift(a: u64, b: u64) -> u32 {
    let bits_for_product = log2_upper(a) + log2_upper(b);
    if bits_for_product < 64 {
        0
    } else {
        bits_for_product - 64
    }
}

/// Return an upper bound for the log2 of n.
///
/// This function overestimates whenver n is a power of two, but that doesn't
/// much matter for the uses we're giving it here.
fn log2_upper(n: u64) -> u32 {
    64 - n.leading_zeros()
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn t_clamp() {
        assert_eq!(clamp_to_pos(32), 32);
        assert_eq!(clamp_to_pos(std::i32::MAX), std::i32::MAX as u32);
        assert_eq!(clamp_to_pos(0), 0);
        assert_eq!(clamp_to_pos(-1), 0);
        assert_eq!(clamp_to_pos(std::i32::MIN), 0);
    }

    #[test]
    fn t_log2() {
        assert_eq!(log2_upper(std::u64::MAX), 64);
        assert_eq!(log2_upper(0), 0);
        assert_eq!(log2_upper(1), 1);
        assert_eq!(log2_upper(63), 6);
        assert_eq!(log2_upper(64), 7); // a little buggy but harmless.
    }

    #[test]
    fn t_calc_shift() {
        assert_eq!(calculate_shift(1 << 20, 1 << 20), 0);
        assert_eq!(calculate_shift(1 << 50, 1 << 10), 0);
        assert_eq!(calculate_shift(1 << 32, 1 << 33), 3);
        assert!(((1_u64 << 32) >> 3).checked_mul(1_u64 << 33).is_some());
        assert_eq!(calculate_shift(432 << 40, 7777 << 40), 38);
        assert!(((432_u64 << 40) >> 38)
            .checked_mul(7777_u64 << 40)
            .is_some());
    }

    #[test]
    fn t_pick_bwfunc() {
        let empty = [];
        assert_eq!(pick_bandwidth_fn(empty.iter()), BandwidthFn::Uniform);

        let all_zero = [
            RouterWeight::Unmeasured(0),
            RouterWeight::Measured(0),
            RouterWeight::Unmeasured(0),
        ];
        assert_eq!(pick_bandwidth_fn(all_zero.iter()), BandwidthFn::Uniform);

        let all_unmeasured = [RouterWeight::Unmeasured(9), RouterWeight::Unmeasured(2222)];
        assert_eq!(
            pick_bandwidth_fn(all_unmeasured.iter()),
            BandwidthFn::IncludeUnmeasured
        );

        let some_measured = [
            RouterWeight::Unmeasured(10),
            RouterWeight::Measured(7),
            RouterWeight::Measured(4),
            RouterWeight::Unmeasured(0),
        ];
        assert_eq!(
            pick_bandwidth_fn(some_measured.iter()),
            BandwidthFn::MeasuredOnly
        );

        // This corresponds to an open question in
        // `pick_bandwidth_fn`, about what to do when the only nonzero
        // weights are unmeasured.
        let measured_all_zero = [RouterWeight::Unmeasured(10), RouterWeight::Measured(0)];
        assert_eq!(
            pick_bandwidth_fn(measured_all_zero.iter()),
            BandwidthFn::Uniform
        );
    }

    #[test]
    fn t_apply_bwfn() {
        use BandwidthFn::*;
        use RouterWeight::*;

        assert_eq!(Uniform.apply(&Measured(7)), 1);
        assert_eq!(Uniform.apply(&Unmeasured(0)), 1);

        assert_eq!(IncludeUnmeasured.apply(&Measured(7)), 7);
        assert_eq!(IncludeUnmeasured.apply(&Unmeasured(8)), 8);

        assert_eq!(MeasuredOnly.apply(&Measured(9)), 9);
        assert_eq!(MeasuredOnly.apply(&Unmeasured(10)), 0);
    }

    // From a fairly recent Tor consensus.
    const TESTVEC_PARAMS: &str =
        "Wbd=0 Wbe=0 Wbg=4096 Wbm=10000 Wdb=10000 Web=10000 Wed=10000 Wee=10000 Weg=10000 Wem=10000 Wgb=10000 Wgd=0 Wgg=5904 Wgm=5904 Wmb=10000 Wmd=0 Wme=0 Wmg=4096 Wmm=10000";

    #[test]
    fn t_weightset_basic() {
        let total_bandwidth = 1_000_000_000;
        let params = TESTVEC_PARAMS.parse().unwrap();
        let ws = WeightSet::from_parts(BandwidthFn::MeasuredOnly, total_bandwidth, 10000, &params);

        assert_eq!(ws.bandwidth_fn, BandwidthFn::MeasuredOnly);
        assert_eq!(ws.shift, 0);

        assert_eq!(ws.w[0].as_guard, 5904);
        assert_eq!(ws.w[(FLG_GUARD) as usize].as_guard, 5904);
        assert_eq!(ws.w[(FLG_EXIT) as usize].as_exit, 10000);
        assert_eq!(ws.w[(FLG_EXIT | FLG_GUARD) as usize].as_dir, 0);
        assert_eq!(ws.w[(FLG_GUARD) as usize].as_dir, 4096);
        assert_eq!(ws.w[(FLG_GUARD | FLG_DIR) as usize].as_dir, 4096);

        assert_eq!(
            ws.weight_bw_for_role(
                WeightKind(FLG_GUARD | FLG_DIR),
                &RouterWeight::Unmeasured(7777),
                WeightRole::Guard
            ),
            0
        );

        assert_eq!(
            ws.weight_bw_for_role(
                WeightKind(FLG_GUARD | FLG_DIR),
                &RouterWeight::Measured(7777),
                WeightRole::Guard
            ),
            7777 * 5904
        );

        assert_eq!(
            ws.weight_bw_for_role(
                WeightKind(FLG_GUARD | FLG_DIR),
                &RouterWeight::Measured(7777),
                WeightRole::Middle
            ),
            7777 * 4096
        );

        assert_eq!(
            ws.weight_bw_for_role(
                WeightKind(FLG_GUARD | FLG_DIR),
                &RouterWeight::Measured(7777),
                WeightRole::Exit
            ),
            7777 * 10000
        );

        assert_eq!(
            ws.weight_bw_for_role(
                WeightKind(FLG_GUARD | FLG_DIR),
                &RouterWeight::Measured(7777),
                WeightRole::BeginDir
            ),
            7777 * 4096
        );

        assert_eq!(
            ws.weight_bw_for_role(
                WeightKind(FLG_GUARD | FLG_DIR),
                &RouterWeight::Measured(7777),
                WeightRole::Unweighted
            ),
            7777
        );
    }
}
