import type { SolutionTree } from '../api.models';
import { asSchema } from './contract';

/**
 * A solutions tree as `GET /api/v1/solutions` sends it: Payments, partly seen (Gateway through one
 * repository, Ledger whole with an image numbered like a repository), Mobile with one empty project,
 * and "No project" holding a repository and an image.
 */
export const openIssues = (critical: number, high: number, medium = 0) =>
    asSchema('OpenIssues', {
        critical,
        high,
        medium,
        low: 0,
        negligible: 0,
        unknown: 0,
        total: critical + high + medium
    });

export const SOLUTION_TREE: SolutionTree = asSchema('SolutionTree', {
    solutions: [
        {
            id: 1,
            name: 'Payments',
            description: 'The payments platform',
            createdAt: '2026-09-01T00:00:00Z',
            partial: true,
            repositoryCount: 2,
            containerCount: 1,
            openIssues: openIssues(2, 1),
            projects: [
                {
                    id: 11,
                    solutionId: 1,
                    name: 'Gateway',
                    description: null,
                    createdAt: '2026-09-01T00:00:00Z',
                    partial: true,
                    checklistsVisible: false,
                    repositoryCount: 1,
                    containerCount: 0,
                    openIssues: openIssues(2, 0),
                    repositories: [{ id: 9, name: 'api-gateway' }],
                    detectedLanguages: [],
                    languagesUnknownFor: []
                },
                {
                    id: 12,
                    solutionId: 1,
                    name: 'Ledger',
                    description: null,
                    createdAt: '2026-09-01T00:00:00Z',
                    partial: false,
                    checklistsVisible: true,
                    repositoryCount: 1,
                    containerCount: 1,
                    openIssues: openIssues(0, 1),
                    repositories: [{ id: 10, name: 'ledger-core' }],
                    // Numbered like api-gateway on purpose: repository 9 and image 9 are two
                    // targets, and only the route tells them apart.
                    containers: [{ id: 9, name: 'ghcr.io/acme/ledger:1.4' }],
                    detectedLanguages: [],
                    languagesUnknownFor: []
                }
            ]
        },
        {
            id: 2,
            name: 'Mobile',
            description: null,
            createdAt: '2026-09-02T00:00:00Z',
            partial: false,
            repositoryCount: 0,
            containerCount: 0,
            openIssues: openIssues(0, 0),
            projects: [
                {
                    id: 21,
                    solutionId: 2,
                    name: 'App',
                    description: null,
                    createdAt: '2026-09-02T00:00:00Z',
                    partial: false,
                    checklistsVisible: true,
                    repositoryCount: 0,
                    containerCount: 0,
                    openIssues: openIssues(0, 0),
                    repositories: [],
                    detectedLanguages: [],
                    languagesUnknownFor: []
                }
            ]
        }
    ],
    unfiled: {
        repositoryCount: 1,
        containerCount: 1,
        openIssues: openIssues(0, 0, 4),
        repositories: [{ id: 30, name: 'legacy-batch' }],
        containers: [{ id: 31, name: 'nginx:1.27' }]
    }
});
