/**
 * Durable Object for precise per-IP rate limiting.
 * Each IP gets its own DO instance via id-from-name.
 * Stores a sliding window counter with atomic read-increment-write.
 */

const RATE_LIMIT = 60;
const RATE_WINDOW = 3600; // 1 hour in seconds

interface RateLimitState {
  start: number;
  count: number;
}

export class RateLimiterDO implements DurableObject {
  private state: DurableObjectState;

  constructor(state: DurableObjectState) {
    this.state = state;
  }

  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);

    if (url.pathname === '/check') {
      return this.check();
    }

    if (url.pathname === '/peek') {
      return this.peek();
    }

    return new Response('Not found', { status: 404 });
  }

  /** Increment counter and return rate limit status */
  private async check(): Promise<Response> {
    const now = Math.floor(Date.now() / 1000);
    let window = await this.state.storage.get<RateLimitState>('window');

    // Reset if expired or missing
    if (!window || now - window.start >= RATE_WINDOW) {
      window = { start: now, count: 0 };
    }

    if (window.count >= RATE_LIMIT) {
      const retryAfter = RATE_WINDOW - (now - window.start);
      return Response.json({
        allowed: false,
        remaining: 0,
        retryAfter,
      });
    }

    window.count++;
    await this.state.storage.put('window', window);

    // Schedule alarm to clean up storage after window expires
    const alarmTime = (window.start + RATE_WINDOW) * 1000;
    const currentAlarm = await this.state.storage.getAlarm();
    if (!currentAlarm) {
      await this.state.storage.setAlarm(alarmTime);
    }

    return Response.json({
      allowed: true,
      remaining: RATE_LIMIT - window.count,
    });
  }

  /** Read current state without incrementing */
  private async peek(): Promise<Response> {
    const now = Math.floor(Date.now() / 1000);
    const window = await this.state.storage.get<RateLimitState>('window');

    if (!window || now - window.start >= RATE_WINDOW) {
      return Response.json({ remaining: RATE_LIMIT });
    }

    return Response.json({
      remaining: Math.max(0, RATE_LIMIT - window.count),
    });
  }

  /** Clean up expired state to avoid paying for idle storage */
  async alarm(): Promise<void> {
    const now = Math.floor(Date.now() / 1000);
    const window = await this.state.storage.get<RateLimitState>('window');

    if (window && now - window.start >= RATE_WINDOW) {
      await this.state.storage.deleteAll();
    }
  }
}
