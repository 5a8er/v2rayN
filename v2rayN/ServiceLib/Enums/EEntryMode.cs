namespace ServiceLib.Enums;

public enum EEntryMode
{
    // Each chain enters through the server picked for it by hand
    Manual,

    // The best carrier is frozen per chain until the entry toggle or mode changes
    Frozen,

    // Frozen, but a carrier that stays unreachable for a minute is replaced by a fresh best pick
    Failover,
}
