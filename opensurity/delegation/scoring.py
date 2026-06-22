from datetime import datetime, timezone
from typing import List

from opensurity.log.events import TrustEvent


def compute_score(
    events: List[TrustEvent],
    capability_id: str,
    recency_window_days: int = 30
) -> float:
    """
    Computes the trust score for an agent.
    
    score = (success_count / total_count) * recency_weight * capability_match
    
    recency_weight: events in last recency_window_days count 1.0,
                    older events decay linearly to 0.5
    
    capability_match: 1.0 if events include the requested capability_id,
                      0.7 otherwise (agent has general track record)
    
    Returns float in [0.0, 1.0]
    Returns 0.5 (neutral) if no events exist
    """
    if not events:
        return 0.5

    total_count = len(events)
    success_count = sum(1 for e in events if e.outcome == "success")
    
    now = datetime.now(timezone.utc)
    weights = []
    
    capability_match = 0.7
    
    for event in events:
        # Check capability
        if event.capability_used == capability_id:
            capability_match = 1.0
            
        # Parse timestamp
        # Assume ISO 8601 with Z or +offset
        timestamp_str = event.timestamp.replace("Z", "+00:00")
        try:
            event_time = datetime.fromisoformat(timestamp_str)
            # Ensure aware
            if event_time.tzinfo is None:
                event_time = event_time.replace(tzinfo=timezone.utc)
            
            age_days = (now - event_time).days
            
            if age_days <= recency_window_days:
                weights.append(1.0)
            else:
                # Decay to 0.5 over an arbitrary period, e.g., the next 60 days
                # Cap the minimum weight at 0.5
                decay_period = 60.0
                decay = (age_days - recency_window_days) / decay_period
                weights.append(max(0.5, 1.0 - 0.5 * decay))
                
        except ValueError:
            # Fallback for unparseable timestamp
            weights.append(0.5)

    recency_weight = sum(weights) / len(weights)
    
    success_rate = success_count / total_count
    
    score = success_rate * recency_weight * capability_match
    
    # Clamp between 0.0 and 1.0
    return max(0.0, min(1.0, score))
