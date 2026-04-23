import { ComponentFixture, TestBed } from '@angular/core/testing';

import { RepoList } from './repo-list';

describe('RepoList', () => {
  let component: RepoList;
  let fixture: ComponentFixture<RepoList>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [RepoList],
    }).compileComponents();

    fixture = TestBed.createComponent(RepoList);
    component = fixture.componentInstance;
    await fixture.whenStable();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
