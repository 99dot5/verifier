// @vitest-environment node
/**
 * The prefix rule `replayTranscript` owns: which actions of a transcript are
 * replayed, and when an unknown action tag rejects the round. The engines'
 * maths is pinned per game against `vectors.json`; this file pins only the
 * selection around them.
 */
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { REPLAYERS, UnknownActionTagError, UnsupportedGameError, replayTranscript, supportedGameTypes } from './replay';
import * as hilo from './verify/hilo';
import { GAME_SEED_DERIVATIONS, hexToBytes } from './verify/seed';
import { ReplayError } from './verify/types';
import { vectorsUrl } from './verify/vectors-path';
import { actionTypeOf, tagOf } from './wire/action-tags';
import type { RoundTranscriptMessage, TranscriptActionWire } from './wire/messages';

interface HexScenario {
    name: string;
    server_seed_hex: string;
    effective_client_seed_hex: string;
}

/** Seeds come from a NAMED scenario, so this file follows the vectors instead of pinning one. */
function hiloScenario(name: string): HexScenario {
    const file: { hex_scenarios?: HexScenario[] } = JSON.parse(
        readFileSync(fileURLToPath(vectorsUrl('hilo')), 'utf8'),
    );
    const scenario = file.hex_scenarios?.find((candidate) => candidate.name === name);

    if (scenario === undefined) {
        throw new Error(`hilo vectors.json has no hex_scenarios entry named ${name}`);
    }

    return scenario;
}

const SCENARIO = hiloScenario('hilo-higher-wins-at-1');
const STAKE = 100_000_000n;
const UNKNOWN_TAG = 0x7f;

function action(actionType: string, payload: Uint8Array = new Uint8Array()): TranscriptActionWire {
    const tag = tagOf(actionType);

    if (tag === null) {
        throw new Error(`no tag for ${actionType}`);
    }

    return { tag, actionType: actionTypeOf(tag), payload };
}

function unknown(): TranscriptActionWire {
    return { tag: UNKNOWN_TAG, actionType: actionTypeOf(UNKNOWN_TAG), payload: new Uint8Array([0xde, 0xad]) };
}

function transcript(actions: TranscriptActionWire[], gameType: string = hilo.v1.GAME_TYPE): RoundTranscriptMessage {
    return {
        kind: 'round-transcript',
        roundId: '9a256790-c7c0-47b0-9a5b-6ed2905d2df1',
        sessionId: 'e2b6419a-ec4b-4eef-bdfa-802b6f338fc2',
        gameType,
        stake: STAKE,
        clientSeed: hexToBytes(SCENARIO.effective_client_seed_hex),
        serverSeed: hexToBytes(SCENARIO.server_seed_hex),
        serverSeedIndex: 137n,
        claimedPayout: 0n,
        playerCommitment: new Uint8Array(32),
        actions,
    };
}

describe('replayTranscript', () => {
    it('has a replayer for every game version that names a seed derivation', () => {
        expect([...supportedGameTypes()].sort()).toEqual(Object.keys(GAME_SEED_DERIVATIONS).sort());
        expect(Object.keys(REPLAYERS).sort()).toEqual([...supportedGameTypes()].sort());
    });

    it('replays a whole transcript through the replayer its game type selects', () => {
        const result = replayTranscript(transcript([action('place-bet'), action('cashout')]));
        const direct = hilo.v1.replay(
            SCENARIO.server_seed_hex,
            SCENARIO.effective_client_seed_hex,
            [
                { actionIndex: 0, actionType: 'place-bet', payload: new Uint8Array() },
                { actionIndex: 1, actionType: 'cashout', payload: new Uint8Array() },
            ],
            STAKE,
        );

        expect(result).toEqual(direct);
        expect(result.settled).toBe(true);
        expect(result.settledAtIndex).toBe(1);
    });

    it('refuses a game type with no replayer', () => {
        expect(() => replayTranscript(transcript([action('place-bet')], 'labours:v1'))).toThrow(UnsupportedGameError);
    });

    it('rejects a transcript whose walk reaches an unknown tag before the settle', () => {
        expect(() => replayTranscript(transcript([action('place-bet'), unknown()]))).toThrow(UnknownActionTagError);
        expect(() => replayTranscript(transcript([action('place-bet'), unknown()]))).toThrow('0x7f');
    });

    it('rejects an unknown tag at index 0, where nothing is left to replay', () => {
        expect(() => replayTranscript(transcript([unknown(), action('cashout')]))).toThrow(UnknownActionTagError);
    });

    it('never reads an unknown tag after the settle, and replays the prefix before it', () => {
        const result = replayTranscript(transcript([action('place-bet'), action('cashout'), unknown()]));
        const prefixOnly = replayTranscript(transcript([action('place-bet'), action('cashout')]));

        expect(result.settled).toBe(true);
        expect(result.settledAtIndex).toBe(1);
        expect(result.payoutUnits).toBe(prefixOnly.payoutUnits);
    });

    it('still hands an empty transcript to the replayer, which refuses it', () => {
        expect(() => replayTranscript(transcript([]))).toThrow(ReplayError);
    });
});
